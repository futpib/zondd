import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:yaml/yaml.dart';
import 'package:zondd_control/control.dart';
import 'package:zondd_control/main.dart';
import 'package:zondd_control/rules.dart';

Map<String, dynamic> reviewDocument() => {
  'version': 1,
  'title': 'deploy',
  'sections': [
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
  bool revoked = false;
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
      return {
        'requests': [],
        'proposals': resolution == null ? [proposal] : [],
      };
    }
    if (body['method'] == 'resolve_rule') {
      resolution = body;
      return {'type': 'rule_resolved'};
    }
    if (body['method'] == 'rules') {
      return {
        'rules': [
          {
            'proposal': proposal,
            'status': revoked ? 'revoked' : 'active',
            'reason': 'Rule state',
          },
        ],
      };
    }
    if (body['method'] == 'revoke_rule') {
      revoked = true;
      return {'type': 'rule_revoked'};
    }
    throw StateError('unexpected method');
  }
}

void main() {
  testWidgets(
    'unsupported review does not prevent revoking an existing grant',
    (tester) async {
      final api = RuleControl();
      api.proposal['review'] = {...reviewDocument(), 'version': 2};
      await tester.pumpWidget(MaterialApp(home: RulesPage(api: api)));
      await tester.pumpAndSettle();
      expect(find.text('Complete rule data (YAML)'), findsOneWidget);
      await tester.ensureVisible(find.text('Revoke rule'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Revoke rule'));
      await tester.pumpAndSettle();
      expect(api.revoked, isTrue);
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
        expect(find.textContaining('repo-name'), findsNothing);
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
