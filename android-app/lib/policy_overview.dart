import 'package:toml/toml.dart';

// Check the shapes consumed by the overview. The remote helper remains the
// authority for full policy validation, including fields not displayed here.
Map<String, dynamic> parsePolicyOverview(String content) {
  final policy = TomlDocument.parse(content).toMap();
  Map table(dynamic value) {
    if (value == null) return {};
    if (value is! Map) throw const FormatException('Expected a table');
    return value;
  }

  List list(dynamic value) {
    if (value == null) return [];
    if (value is! List) throw const FormatException('Expected an array');
    return value;
  }

  void scalar<T>(Map value, String key) {
    if (value.containsKey(key) && value[key] is! T) {
      throw FormatException('Invalid $key');
    }
  }

  void strings(dynamic value) {
    for (final item in list(value)) {
      if (item is! String) throw const FormatException('Expected a string');
    }
  }

  final approvals = table(policy['approvals']);
  scalar<bool>(approvals, 'enabled');
  scalar<int>(approvals, 'timeout_secs');
  for (final value in table(policy['principals']).values) {
    final principal = table(value);
    scalar<bool>(principal, 'allow_exec');
    scalar<String>(principal, 'default');
    scalar<String>(principal, 'cwd');
    strings(principal['operations']);
    for (final value in list(principal['rules'])) {
      final rule = table(value);
      scalar<String>(rule, 'decision');
      scalar<String>(rule, 'program');
      strings(rule['args']);
    }
  }
  for (final value in table(policy['operations']).values) {
    final operation = table(value);
    for (final field in ['description', 'program', 'decision']) {
      scalar<String>(operation, field);
    }
    strings(operation['fixed_args']);
    for (final value in list(operation['arguments'])) {
      final argument = table(value);
      scalar<String>(argument, 'name');
      strings(argument['choices']);
    }
  }
  return policy;
}
