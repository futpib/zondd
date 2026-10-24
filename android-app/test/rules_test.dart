import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:yaml/yaml.dart';
import 'package:zondd_control/control.dart';
import 'package:zondd_control/main.dart';
import 'package:zondd_control/rules.dart';

const normalizedDefinition =
    'rule deploy(ticket: ticket-id) { run /usr/bin/deploy }';

Map<String, dynamic> reviewDocument() => {
  'version': 1,
  'title': 'deploy',
  'sections': [
    {
      'title': 'Normalized rule',
      'fields': [
        {'label': 'Definition', 'value': normalizedDefinition},
      ],
    },
    {
      'title': 'Authority',
      'fields': [
        {
          'label': 'Grant',
          'value':
              'Repeated invocations by this principal (including every assigned key).',
        },
      ],
    },
    {
      'title': 'New daemon vocabulary',
      'fields': [
        {'label': 'ticket: ticket-id', 'value': 'Full match: PROJ-[0-9]{1,6}.'},
        {
          'label': 'require on-branch',
          'value': 'The working tree must be on the release branch.',
        },
        {
          'label': 'publish-file',
          'value': 'Publish one file only after success, without replacement.',
        },
      ],
    },
  ],
};

class RuleControl implements ControlApi {
  Map<String, dynamic>? resolution;
  String? resolutionError, pendingError;
  int resolutionAttempts = 0;
  int revocations = 0;
  final revokedIds = <String>{};
  final extraRules = <Map<String, dynamic>>[];
  bool get revoked => revokedIds.contains(proposal['id']);
  final Map<String, dynamic> proposal = {
    'id': 'proposal-1',
    'principal': 'caller',
    'digest': 'exact-reviewed-digest',
    'source': 'A rule using syntax added by a future daemon',
    'review': reviewDocument(),
  };

  @override
  Future<void> close() async {}
  @override
  Future<Map<String, dynamic>> request(Map<String, dynamic> body) async {
    if (body['method'] == 'pending') {
      if (pendingError != null) throw StateError(pendingError!);
      return {
        'requests': [],
        'proposals': resolution == null ? [proposal] : [],
      };
    }
    if (body['method'] == 'resolve_rule') {
      resolutionAttempts++;
      if (resolutionError != null) throw StateError(resolutionError!);
      resolution = body;
      return {'type': 'rule_resolved'};
    }
    if (body['method'] == 'rules') {
      return {
        'rules':
            [
                  ...extraRules,
                  {
                    'proposal': proposal,
                    'status': revoked ? 'revoked' : 'active',
                    'reason': 'Rule state',
                  },
                ]
                .map(
                  (state) => {
                    ...state,
                    if (revokedIds.contains(state['proposal']['id']))
                      'status': 'revoked',
                  },
                )
                .toList(),
      };
    }
    if (body['method'] == 'revoke_rule') {
      revocations++;
      revokedIds.add(body['grant_id'] as String);
      return {'type': 'rule_revoked'};
    }
    throw StateError('unexpected method');
  }
}

class LostRevokeReply implements ControlApi {
  LostRevokeReply(this.server);
  final RuleControl server;
  bool lost = false;
  @override
  Future<void> close() async {}
  @override
  Future<Map<String, dynamic>> request(Map<String, dynamic> body) async {
    if (lost) throw const ConnectionLost();
    final result = await server.request(body);
    if (body['method'] == 'revoke_rule') {
      lost = true;
      throw const ConnectionLost();
    }
    return result;
  }
}

void main() {
  for (final approve in [true, false]) {
    testWidgets('rule decision $approve keeps failures visible across polls', (
      tester,
    ) async {
      final api = RuleControl()..resolutionError = 'Rule decision failed';
      await tester.pumpWidget(
        MaterialApp(
          home: Dashboard(api: api, name: 'Review'),
        ),
      );
      await tester.pumpAndSettle();
      final decision = find.text(approve ? 'Approve rule' : 'Reject rule');
      await tester.ensureVisible(decision);
      await tester.pumpAndSettle();
      await tester.tap(decision);
      await tester.pumpAndSettle();
      expect(api.resolutionAttempts, 1);
      expect(find.textContaining('Rule decision failed'), findsOneWidget);
      await tester.pump(const Duration(seconds: 2));
      await tester.pumpAndSettle();
      expect(find.textContaining('Rule decision failed'), findsOneWidget);
      expect(api.resolution, isNull);
      api.resolutionError = null;
      await tester.ensureVisible(decision);
      await tester.pumpAndSettle();
      await tester.tap(decision);
      await tester.pumpAndSettle();
      expect(find.textContaining('Rule decision failed'), findsNothing);
      expect(api.resolution?['approve'], approve);
      await tester.pumpWidget(const SizedBox.shrink());
    });
  }

  testWidgets('a recovered approvals poll clears its own error', (
    tester,
  ) async {
    final api = RuleControl()..pendingError = 'Pending requests unavailable';
    await tester.pumpWidget(
      MaterialApp(
        home: Dashboard(api: api, name: 'Review'),
      ),
    );
    await tester.pumpAndSettle();
    expect(find.textContaining('Pending requests unavailable'), findsOneWidget);
    expect(find.byType(CircularProgressIndicator), findsNothing);
    api.pendingError = null;
    await tester.pump(const Duration(seconds: 2));
    await tester.pumpAndSettle();
    expect(find.textContaining('Pending requests unavailable'), findsNothing);
    expect(find.text('Reusable rule proposal'), findsOneWidget);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets(
    'rules recover a lost revoke reply without losing the filter or replaying',
    (tester) async {
      final server = RuleControl();
      final api = ControlConnection(
        LostRevokeReply(server),
        () async => server,
      );
      await tester.pumpWidget(MaterialApp(home: RulesPage(api: api)));
      await tester.pumpAndSettle();
      await tester.tap(find.text('All'));
      await tester.pumpAndSettle();
      await tester.enterText(find.byType(TextField), 'deploy');
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const ValueKey('rule-expand-proposal-1')));
      await tester.pumpAndSettle();
      await tester.ensureVisible(find.text('Revoke rule'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Revoke rule'));
      await tester.pumpAndSettle();
      expect(api.disconnected, isTrue);
      await tester.pump(const Duration(seconds: 1));
      await tester.pumpAndSettle();
      expect(api.disconnected, isFalse);
      expect(server.revocations, 1);
      expect(
        tester.widget<TextField>(find.byType(TextField)).controller!.text,
        'deploy',
      );
      expect(find.byType(RuleDefinition), findsOneWidget);
      await tester.drag(find.byType(ListView), const Offset(0, 10000));
      await tester.pumpAndSettle();
      expect(find.text('Status: revoked'), findsOneWidget);
      await tester.pumpWidget(const SizedBox.shrink());
      await api.close();
      api.dispose();
    },
  );

  testWidgets(
    'review shows received source before daemon definition and YAML details',
    (tester) async {
      final proposal = RuleControl().proposal;
      proposal['source'] =
          '# Keep source formatting\nrule deploy(ticket: ticket-id) {\n  run deploy\n}\n';
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: SingleChildScrollView(
              child: RuleDefinition(proposal: proposal),
            ),
          ),
        ),
      );
      expect(find.text('Definition: $normalizedDefinition'), findsOneWidget);
      final source = find.byKey(const ValueKey('rule-source-proposal-1'));
      expect(tester.widget<SelectableText>(source).data, proposal['source']);
      expect(find.text('As received by the daemon'), findsOneWidget);
      expect(
        tester.getTopLeft(source).dy,
        lessThan(tester.getTopLeft(find.text('Normalized rule')).dy),
      );
      expect(find.byKey(const ValueKey('rule-yaml-proposal-1')), findsNothing);
      await tester.ensureVisible(find.text('Rule details (YAML)'));
      await tester.tap(find.text('Rule details (YAML)'));
      await tester.pumpAndSettle();
      final yaml = tester
          .widget<SelectableText>(
            find.byKey(const ValueKey('rule-yaml-proposal-1')),
          )
          .data!;
      expect(loadYaml(yaml), equals(proposal));
      expect(loadYaml(yaml)['source'], proposal['source']);
    },
  );

  Map<String, dynamic> otherRule({
    String id = 'proposal-2',
    String title = 'clone',
    String status = 'expired',
  }) => {
    'proposal': {
      'id': id,
      'principal': 'builder',
      'source': 'run git clone example',
      'review': {
        'version': 1,
        'title': title,
        'sections': [
          {
            'title': 'Command',
            'fields': [
              {'label': 'Program', 'value': 'git'},
            ],
          },
        ],
      },
    },
    'status': status,
    'reason': 'Grant lifetime elapsed',
  };

  testWidgets(
    'current rules start collapsed with active before pending and history hidden',
    (tester) async {
      final api = RuleControl()
        ..extraRules.addAll([
          otherRule(),
          otherRule(id: 'pending', title: 'waiting', status: 'pending'),
        ]);
      await tester.pumpWidget(MaterialApp(home: RulesPage(api: api)));
      await tester.pumpAndSettle();
      expect(find.text('2 rules'), findsOneWidget);
      expect(find.text('deploy'), findsOneWidget);
      expect(find.text('Caller: caller'), findsOneWidget);
      expect(find.text('Status: active'), findsOneWidget);
      expect(find.text('Valid until revoked'), findsOneWidget);
      expect(find.text('Status: expired'), findsNothing);
      expect(find.text('Status: pending'), findsOneWidget);
      expect(
        tester.getTopLeft(find.text('deploy')).dy,
        lessThan(tester.getTopLeft(find.text('waiting')).dy),
      );
      expect(find.byType(RuleDefinition), findsNothing);
      expect(find.text('Revoke rule'), findsNothing);
      await tester.tap(find.text('deploy'));
      await tester.pumpAndSettle();
      expect(find.text('Definition: $normalizedDefinition'), findsOneWidget);
      expect(find.text(api.proposal['source']), findsOneWidget);
      expect(find.text('New daemon vocabulary'), findsOneWidget);
      await tester.tap(find.text('deploy'));
      await tester.pumpAndSettle();
      expect(find.byType(RuleDefinition), findsNothing);
      await tester.tap(find.text('All'));
      await tester.pumpAndSettle();
      expect(find.text('3 rules'), findsOneWidget);
      expect(
        tester.getTopLeft(find.text('waiting')).dy,
        lessThan(tester.getTopLeft(find.text('clone')).dy),
      );
      await tester.tap(find.text('History'));
      await tester.pumpAndSettle();
      expect(find.text('1 rule'), findsOneWidget);
      expect(find.text('Status: expired'), findsOneWidget);
      expect(find.text('Status: active'), findsNothing);
      expect(find.text('Status: pending'), findsNothing);
    },
  );

  testWidgets(
    'search finds hidden and future data, with clear and empty states',
    (tester) async {
      final api = RuleControl()..extraRules.add(otherRule());
      api.proposal['future_check'] = {'condition': 'Special constraint'};
      await tester.pumpWidget(MaterialApp(home: RulesPage(api: api)));
      await tester.pumpAndSettle();
      await tester.enterText(find.byType(TextField), 'expired');
      await tester.pumpAndSettle();
      expect(find.text('No rules match your search.'), findsOneWidget);
      await tester.tap(find.text('History'));
      await tester.pumpAndSettle();
      expect(find.text('clone'), findsOneWidget);
      expect(find.text('1 of 1 rules'), findsOneWidget);
      await tester.tap(find.text('All'));
      await tester.pumpAndSettle();
      for (final query in [
        '  DEPLOY  ',
        'caller',
        'future daemon',
        'release branch',
        'special constraint',
        'proposal-1',
        'exact-reviewed-digest',
      ]) {
        await tester.enterText(find.byType(TextField), query);
        await tester.pumpAndSettle();
        expect(find.text('1 of 2 rules'), findsOneWidget, reason: query);
        expect(find.text('deploy'), findsOneWidget, reason: query);
        expect(find.text('clone'), findsNothing, reason: query);
        expect(find.byType(RuleDefinition), findsNothing);
      }
      for (final query in ['builder', 'expired', 'lifetime elapsed']) {
        await tester.enterText(find.byType(TextField), query);
        await tester.pumpAndSettle();
        expect(find.text('clone'), findsOneWidget, reason: query);
        expect(find.text('deploy'), findsNothing, reason: query);
      }
      await tester.enterText(find.byType(TextField), 'no-such-rule');
      await tester.pumpAndSettle();
      expect(find.text('0 of 2 rules'), findsOneWidget);
      expect(find.text('No rules match your search.'), findsOneWidget);
      await tester.tap(find.byTooltip('Clear search'));
      await tester.pumpAndSettle();
      expect(find.text('2 rules'), findsOneWidget);
      expect(find.text('deploy'), findsOneWidget);
      expect(find.text('clone'), findsOneWidget);
      expect(find.byTooltip('Clear search'), findsNothing);
    },
  );

  testWidgets(
    'expansion follows the rule across filtering, refresh and revoke',
    (tester) async {
      final api = RuleControl()..extraRules.add(otherRule());
      await tester.pumpWidget(MaterialApp(home: RulesPage(api: api)));
      await tester.pumpAndSettle();
      await tester.tap(find.text('All'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('deploy'));
      await tester.pumpAndSettle();
      await tester.enterText(find.byType(TextField), 'clone');
      await tester.pumpAndSettle();
      expect(find.byType(RuleDefinition), findsNothing);
      await tester.enterText(find.byType(TextField), 'deploy');
      await tester.pumpAndSettle();
      expect(find.text('Definition: $normalizedDefinition'), findsOneWidget);
      expect(find.text(api.proposal['source']), findsOneWidget);
      await tester.tap(find.byTooltip('Refresh rules'));
      await tester.pumpAndSettle();
      expect(find.text('1 of 2 rules'), findsOneWidget);
      expect(find.text('Definition: $normalizedDefinition'), findsOneWidget);
      expect(find.text(api.proposal['source']), findsOneWidget);
      await tester.ensureVisible(find.text('Revoke rule'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Revoke rule'));
      await tester.pumpAndSettle();
      expect(api.revokedIds, {'proposal-1'});
      expect(find.text('Status: revoked'), findsOneWidget);
      expect(find.text('Revoke rule'), findsNothing);
      await tester.tap(find.text('Current'));
      await tester.pumpAndSettle();
      expect(find.byType(RuleDefinition), findsNothing);
      await tester.tap(find.text('History'));
      await tester.pumpAndSettle();
      expect(find.byType(RuleDefinition), findsOneWidget);
      await tester.tap(find.byTooltip('Clear search'));
      await tester.pumpAndSettle();
      expect(find.byType(RuleDefinition), findsOneWidget);
      await tester.drag(find.byType(ListView), const Offset(0, 10000));
      await tester.pumpAndSettle();
      expect(find.text('Status: expired'), findsOneWidget);
    },
  );

  testWidgets(
    'unsupported review does not prevent revoking an existing grant',
    (tester) async {
      final api = RuleControl();
      api.proposal['review'] = {...reviewDocument(), 'version': 2};
      await tester.pumpWidget(MaterialApp(home: RulesPage(api: api)));
      await tester.pumpAndSettle();
      expect(find.text('Complete rule data (YAML)'), findsNothing);
      await tester.tap(find.text('deploy'));
      await tester.pumpAndSettle();
      expect(find.text('Complete rule data (YAML)'), findsOneWidget);
      await tester.ensureVisible(find.text('Revoke rule'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Revoke rule'));
      await tester.pumpAndSettle();
      expect(api.revoked, isTrue);
      expect(find.text('No current rule proposals or grants.'), findsOneWidget);
      expect(find.text('Status: revoked'), findsNothing);
      await tester.tap(find.text('History'));
      await tester.pumpAndSettle();
      expect(find.text('Status: revoked'), findsOneWidget);
    },
  );

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
        expect(find.text('New daemon vocabulary'), findsOneWidget);
        expect(
          find.text('ticket: ticket-id: Full match: PROJ-[0-9]{1,6}.'),
          findsOneWidget,
        );
        expect(find.textContaining('require on-branch:'), findsOneWidget);
        expect(find.textContaining('publish-file:'), findsOneWidget);
        expect(find.textContaining('repository-name'), findsNothing);
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

  final unsupported = <String, Object?>{
    'missing': null,
    'scalar document': 'opaque review text',
    'array document': [
      1,
      {'nested': true},
    ],
    'new version': {...reviewDocument(), 'version': 2},
    'wrong version type': {...reviewDocument(), 'version': '1'},
    'unknown document field': {
      ...reviewDocument(),
      'required_widget': 'approval-scope',
    },
    'empty sections': {...reviewDocument(), 'sections': []},
    'unknown section field': {
      ...reviewDocument(),
      'sections': [
        {
          'title': 'Scope',
          'fields': [
            {'label': 'Grant', 'value': 'Text'},
          ],
          'hidden_constraint': true,
        },
      ],
    },
    'unknown field attribute': {
      ...reviewDocument(),
      'sections': [
        {
          'title': 'Scope',
          'fields': [
            {'label': 'Grant', 'value': 'Text', 'condition': 'unrendered'},
          ],
        },
      ],
    },
    'nontext field': {
      ...reviewDocument(),
      'sections': [
        {
          'title': 'Scope',
          'fields': [
            {
              'label': 'Grant',
              'value': ['unrendered'],
            },
          ],
        },
      ],
    },
    'empty field': {
      ...reviewDocument(),
      'sections': [
        {
          'title': 'Scope',
          'fields': [
            {'label': 'Grant', 'value': ''},
          ],
        },
      ],
    },
  };
  for (final entry in unsupported.entries) {
    for (final approve in [true, false]) {
      testWidgets(
        '${entry.key} review supports YAML review and decision $approve',
        (tester) async {
          final api = RuleControl();
          if (entry.key == 'missing') {
            api.proposal.remove('review');
          } else {
            api.proposal['review'] = entry.value;
          }
          api.proposal['future_definition'] = {
            'nested': [
              {
                'check': 'unrecognized',
                'enabled': false,
                'limit': 3,
                'optional': null,
              },
            ],
          };
          await tester.pumpWidget(
            MaterialApp(
              home: Dashboard(api: api, name: 'test'),
            ),
          );
          await tester.pumpAndSettle();
          expect(tester.takeException(), isNull);
          expect(
            tester
                .widget<FilledButton>(
                  find.widgetWithText(FilledButton, 'Approve rule'),
                )
                .onPressed,
            isNotNull,
          );
          expect(
            tester
                .widget<DropdownButtonFormField<int>>(
                  find.byType(DropdownButtonFormField<int>),
                )
                .onChanged,
            isNotNull,
          );
          expect(find.text('Complete rule data (YAML)'), findsOneWidget);
          final yaml = tester
              .widget<SelectableText>(
                find.byKey(const ValueKey('rule-yaml-proposal-1')),
              )
              .data!;
          expect(loadYaml(yaml), equals(api.proposal));
          expect(find.textContaining('Approval is disabled'), findsNothing);
          final decision = find.text(approve ? 'Approve rule' : 'Reject rule');
          await tester.ensureVisible(decision);
          await tester.pumpAndSettle();
          await tester.tap(decision);
          await tester.pumpAndSettle();
          expect(api.resolution, {
            'method': 'resolve_rule',
            'proposal_id': 'proposal-1',
            'digest': 'exact-reviewed-digest',
            'approve': approve,
            'expires_in_secs': approve ? 3600 : null,
          });
          await tester.pumpWidget(const SizedBox.shrink());
        },
      );
    }
  }

  testWidgets('plain review text is rendered without interpreting markup', (
    tester,
  ) async {
    final proposal = RuleControl().proposal;
    proposal['review'] = {
      'version': 1,
      'title': 'Example',
      'sections': [
        {
          'title': 'Check',
          'fields': [
            {'label': 'Literal', 'value': r'<b>required</b> **text** ${x}'},
          ],
        },
      ],
    };
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(body: RuleDefinition(proposal: proposal)),
      ),
    );
    expect(
      find.text(r'Literal: <b>required</b> **text** ${x}'),
      findsOneWidget,
    );
  });
}
