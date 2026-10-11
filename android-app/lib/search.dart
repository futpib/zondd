import 'package:flutter/material.dart';
import 'json_yaml.dart';

bool matchesSearch(String query, Object? value) =>
    query.trim().isEmpty ||
    jsonAsYaml(value).toLowerCase().contains(query.trim().toLowerCase());

class ListSearchField extends StatelessWidget {
  const ListSearchField({
    super.key,
    required this.controller,
    required this.label,
    required this.hint,
    required this.onChanged,
  });
  final TextEditingController controller;
  final String label, hint;
  final ValueChanged<String> onChanged;

  @override
  Widget build(BuildContext context) => TextField(
    controller: controller,
    onChanged: onChanged,
    onSubmitted: (_) => FocusScope.of(context).unfocus(),
    textInputAction: TextInputAction.search,
    decoration: InputDecoration(
      labelText: label,
      hintText: hint,
      prefixIcon: const Icon(Icons.search),
      suffixIcon: controller.text.isEmpty
          ? null
          : IconButton(
              tooltip: 'Clear search',
              icon: const Icon(Icons.clear),
              onPressed: () {
                controller.clear();
                onChanged('');
              },
            ),
    ),
  );
}
