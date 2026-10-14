import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import MagicMock, patch


def load_function_app():
    # Keep tests offline: importing the function normally fetches Key Vault secrets.
    module_names = [
        'azure', 'azure.functions', 'azure.identity', 'azure.keyvault',
        'azure.keyvault.secrets', 'azure.monitor', 'azure.monitor.query', 'requests',
    ]
    modules = {name: MagicMock() for name in module_names}
    modules['azure'].functions = modules['azure.functions']
    app = modules['azure.functions'].FunctionApp.return_value
    app.function_name.side_effect = lambda **kwargs: lambda function: function
    app.timer_trigger.side_effect = lambda **kwargs: lambda function: function
    spec = importlib.util.spec_from_file_location('function_app', Path(__file__).with_name('function_app.py'))
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {**modules, 'function_app': module}):
        spec.loader.exec_module(module)
    return module


class SearchCasesAlertTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bot = load_function_app()

    def data(self, count, codes=None, operations=None):
        return {'tables': [{'rows': [[count, codes or ['500'], operations or []]]}]}

    def setUp(self):
        self.secret_patch = patch.object(self.bot.secret_client, 'get_secret',
                                         return_value=MagicMock(value='https://example.com/concerning-webhook'))
        self.secret = self.secret_patch.start()
        self.addCleanup(self.secret_patch.stop)

    def test_empty_or_below_threshold_does_not_alert(self):
        self.assertIsNone(self.bot.generate_search_cases_message({'tables': [{'rows': []}]}))
        for count in range(4):
            with self.subTest(count=count):
                self.assertIsNone(self.bot.generate_search_cases_message(self.data(count)))

    def test_threshold_and_higher_generate_distinct_alerts(self):
        for count in (4, 5, 100):
            with self.subTest(count=count):
                message = self.bot.generate_search_cases_message(self.data(count, ['503', '500']))
                self.assertIn(f'{count} failed GET /cases/searchCases', message['text'])
                self.assertIn('This may be a complete Cafcass API blocker.', message['text'])
                attachment = message['attachments'][0]
                self.assertEqual('#d50200', attachment['color'])
                self.assertIn('Concerning issue', attachment['blocks'][0]['text']['text'])
                self.assertIn('500, 503', attachment['blocks'][1]['text']['text'])
                self.assertIn('*This may be a complete Cafcass API blocker.*',
                              attachment['blocks'][1]['text']['text'])

    def test_json_arrays_and_operation_links(self):
        with patch.object(self.bot, 'generate_azure_link', return_value='https://portal.azure.com/example'):
            message = self.bot.generate_search_cases_message(
                self.data(4, json.dumps(['500']), json.dumps(['operation-1'])))
        self.assertIn('<https://portal.azure.com/example|operation-1>',
                      message['attachments'][0]['blocks'][2]['text']['text'])

    def test_operation_examples_are_bounded(self):
        with patch.object(self.bot, 'generate_azure_link', return_value='https://portal.azure.com') as link:
            self.bot.generate_search_cases_message(self.data(20, operations=[f'op-{i}' for i in range(20)]))
        self.assertEqual(10, link.call_count)

    def test_request_query_uses_five_minute_timespan(self):
        response = MagicMock(status=self.bot.LogsQueryStatus.SUCCESS, tables=[])
        with patch.object(self.bot.logs_client, 'query_workspace', return_value=response) as query:
            self.bot.query_application_insights(self.bot.search_cases_query)
        self.assertEqual(self.bot.search_cases_query, query.call_args.kwargs['query'])
        self.assertEqual(300, query.call_args.kwargs['timespan'].total_seconds())

    def test_concerning_alert_does_not_require_exceptions(self):
        with patch.object(self.bot, 'query_application_insights', side_effect=[
            self.data(4), {'tables': [{'rows': []}]},
        ]) as query, patch.object(self.bot, 'send_slack_message') as send:
            self.bot.trigger_function(MagicMock())
        self.assertEqual(2, query.call_count)
        self.assertEqual(1, send.call_count)
        self.assertIn('attachments', send.call_args.args[0])
        self.assertEqual('https://example.com/concerning-webhook', send.call_args.args[1])
        self.secret.assert_called_once_with('concerning-slack-webhook-url')

    def test_both_alerts_are_sent_when_exceptions_also_exist(self):
        with patch.object(self.bot, 'query_application_insights', side_effect=[
            self.data(4), {'tables': [{'rows': [['2026-10-14T12:00:00Z', 'Error', 'Failed', 'op-1']]}]},
        ]), patch.object(self.bot, 'generate_azure_link', return_value='https://portal.azure.com'), \
                patch.object(self.bot, 'send_slack_message') as send:
            self.bot.trigger_function(MagicMock())
        self.assertEqual(2, send.call_count)
        self.assertEqual('New Exception Alert', send.call_args_list[1].args[0]['blocks'][0]['text']['text'])
        self.assertEqual('https://example.com/concerning-webhook', send.call_args_list[0].args[1])
        self.assertEqual(self.bot.slack_webhook_url, send.call_args_list[1].args[1])

    def test_missing_secret_does_not_prevent_exception_alerts(self):
        self.secret.side_effect = RuntimeError('secret unavailable')
        with patch.object(self.bot, 'query_application_insights', side_effect=[
            self.data(4), {'tables': [{'rows': [['2026-10-14T12:00:00Z', 'Error', 'Failed', 'op-1']]}]},
        ]), patch.object(self.bot, 'generate_azure_link', return_value='https://portal.azure.com'), \
                patch.object(self.bot, 'send_slack_message') as send, \
                self.assertLogs(level='ERROR') as logs:
            self.bot.trigger_function(MagicMock())
        self.assertEqual(1, send.call_count)
        self.assertEqual(self.bot.slack_webhook_url, send.call_args.args[1])
        self.assertIn('Concerning alert not sent', logs.output[0])

    def test_empty_secret_does_not_send(self):
        for value in (None, '', '   '):
            with self.subTest(value=value):
                self.secret.return_value.value = value
                with patch.object(self.bot, 'send_slack_message') as send, self.assertLogs(level='ERROR'):
                    self.bot.send_concerning_slack_message({'text': 'alert'})
                send.assert_not_called()

    def test_delivery_failure_is_logged_without_webhook_secret(self):
        with patch.object(self.bot, 'send_slack_message', side_effect=RuntimeError(
            'Failed https://example.com/concerning-webhook')), self.assertLogs(level='ERROR') as logs:
            self.bot.send_concerning_slack_message({'text': 'alert'})
        self.assertNotIn('https://example.com/concerning-webhook', '\n'.join(logs.output))

    def test_slack_delivery_posts_to_the_selected_webhook(self):
        with patch.object(self.bot.requests, 'post') as post:
            self.bot.send_slack_message({'text': 'alert'}, 'https://example.com/concerning-webhook')
        post.assert_called_once_with('https://example.com/concerning-webhook',
                                     json={'text': 'alert'}, timeout=30)
        post.return_value.raise_for_status.assert_called_once_with()


if __name__ == '__main__':
    unittest.main()
