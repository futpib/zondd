import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zondd_control/control.dart';
import 'package:zondd_control/main.dart';

class RuleControl implements ControlApi {
  Map<String, dynamic>? resolution;
  final proposal = {
    'id': 'proposal-1',
    'principal': 'caller',
    'digest': 'exact-reviewed-digest',
    'source': r'rule clone(x: repo-name) { run git clone "$x" }',
    'bound': {
      'home': '/home/receiver',
      'cwd': '/tmp',
      'rule': {
        'name': 'clone',
        'program': '/usr/bin/git',
        'parameters': [
          {'name': 'x', 'kind': 'repo-name'},
        ],
      },
    },
  };

  @override
  Future<void> close() async {}
  @override
  Future<Map<String, dynamic>> request(Map<String, dynamic> body) async {
    if (body['method'] == 'pending') {
      return {
        'requests': [],
        'proposals': resolution == null ? [proposal] : [],
      };
    }
    if (body['method'] == 'resolve_rule') {
      resolution = body;
      return {'type': 'rule_resolved'};
    }
    throw StateError('unexpected method');
  }
}

void main() {
  for (final permanent in [false, true]) {
    testWidgets(
      'rule review submits the exact digest with explicit lifetime $permanent',
      (tester) async {
        final api = RuleControl();
        await tester.pumpWidget(
          MaterialApp(
            home: Dashboard(api: api, name: 'test'),
          ),
        );
        await tester.pumpAndSettle();
        expect(find.text('Approve once'), findsNothing);
        expect(
          find.textContaining('including every assigned key'),
          findsOneWidget,
        );
        if (permanent) {
          await tester.ensureVisible(find.byType(DropdownButtonFormField<int>));
          await tester.pumpAndSettle();
          await tester.tap(find.byType(DropdownButtonFormField<int>));
          await tester.pumpAndSettle();
          await tester.tap(find.text('Until revoked').last);
          await tester.pumpAndSettle();
        }
        await tester.ensureVisible(find.text('Approve rule'));
        await tester.pumpAndSettle();
        await tester.tap(find.text('Approve rule'));
        await tester.pumpAndSettle();
        expect(api.resolution, {
          'method': 'resolve_rule',
          'proposal_id': 'proposal-1',
          'digest': 'exact-reviewed-digest',
          'approve': true,
          'expires_in_secs': permanent ? null : 3600,
        });
        expect(find.text('Reusable rule proposal'), findsNothing);
        await tester.pumpWidget(const SizedBox.shrink());
      },
    );
  }
}
