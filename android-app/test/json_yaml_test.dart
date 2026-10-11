import 'dart:convert';
import 'dart:math';

import 'package:flutter_test/flutter_test.dart';
import 'package:yaml/yaml.dart';
import 'package:zondd_control/json_yaml.dart';

void main() {
  test(
    'YAML preserves JSON scalar types, empty collections and nested data',
    () {
      for (final value in <Object?>[
        null,
        true,
        false,
        0,
        -1,
        9007199254740991,
        0.5,
        -0.0,
        1e25,
        1e-9,
        '',
        'null',
        'true',
        'yes',
        '0',
        '1.5',
        '2026-10-11',
        [],
        {},
        {
          'null': 'null',
          'true': true,
          '<<': {'on': false},
          'items': [[], {}, null],
        },
      ]) {
        final yaml = jsonAsYaml(value);
        final decoded = loadYaml(yaml);
        expect(decoded, equals(value), reason: yaml);
        if (value is num) expect(decoded.runtimeType, value.runtimeType);
      }
      expect(
        jsonAsYaml({
          'nested': {
            'list': [true, 'true'],
          },
        }),
        '"nested":\n  "list":\n    - true\n    - "true"\n',
      );
    },
  );

  test(
    'YAML quotes text so directives, controls and whitespace remain literal',
    () {
      final strings = [
        'line 1\nline 2\n',
        'spaces  \n\n',
        'quote " and slash \\',
        '\t\r\n',
        'a: b\nadmin: true',
        '---\n!!str',
        '*alias',
        '&anchor',
        r'$(id)',
        'é 日本語 😀',
        '\u0085\u2028\u2029\u202e\u2066',
        String.fromCharCodes(List.generate(160, (i) => i)),
      ];
      final value = {for (final text in strings) text: text};
      final yaml = jsonAsYaml(value);
      expect(loadYaml(yaml), equals(value));
      expect(yaml, contains(r'\u0085'));
      expect(yaml, contains(r'\u2028'));
      expect(yaml, contains(r'\u202e'));
      expect(yaml, isNot(contains('\u0085')));
      expect(yaml, isNot(contains('\u202e')));
    },
  );

  test(
    'arbitrary JSON trees round-trip through YAML without losing fields',
    () {
      final random = Random(481);
      Object? tree(int depth) {
        final kind = random.nextInt(depth == 0 ? 5 : 7);
        return switch (kind) {
          0 => null,
          1 => random.nextBool(),
          2 => random.nextInt(100000) - 50000,
          3 => random.nextDouble(),
          4 => String.fromCharCodes(
            List.generate(random.nextInt(20), (_) => random.nextInt(256)),
          ),
          5 => List.generate(random.nextInt(5), (_) => tree(depth - 1)),
          _ => {
            for (var i = 0; i < random.nextInt(5); i++)
              'field $i:': tree(depth - 1),
          },
        };
      }

      for (var i = 0; i < 200; i++) {
        final value = jsonDecode(jsonEncode(tree(4)));
        expect(loadYaml(jsonAsYaml(value)), equals(value));
      }
    },
  );
}
