//! Steady-state storage packing for Tree-sitter-lowered compiler IR.
//!
//! Lowering grows collections geometrically because facts arrive during an
//! AST walk. Once the mutable frontend phase ends, the IR is immutable and
//! unused capacity is pure resident-memory overhead. This module owns that
//! lifecycle boundary so semantic type declarations stay focused on wire and
//! API shape.

use crate::{
    CharacterConstraintDomain, CharacterConstraintOutput, ConditionExpressionFact, Decl, DeclIndex,
    ExpressionFlow, FlowEvent, StaticScalarValue,
};

impl DeclIndex {
    /// Pack completed file-local compiler IR into its steady-state allocation
    /// shape without changing facts or analysis scope.
    pub fn compact_storage(&mut self) {
        for decl in &mut self.defs {
            compact_decl_storage(decl);
        }
        for reference in &mut self.refs {
            reference.name.shrink_to_fit();
        }
        for fact in &mut self.assignment_values {
            compact_optional_string(&mut fact.target);
            fact.call_sites.shrink_to_fit();
            compact_expression_flow_storage(&mut fact.value_flow);
            if let Some(flow) = &mut fact.exact_callable_return {
                compact_expression_flow_storage(flow);
            }
            if let Some(arguments) = &mut fact.exact_static_call_args {
                for argument in arguments.iter_mut() {
                    compact_static_scalar(argument);
                }
                arguments.shrink_to_fit();
            }
            compact_optional_string(&mut fact.direct_call_name);
            compact_optional_string(&mut fact.direct_call_receiver);
        }
        for fact in &mut self.call_receivers {
            compact_expression_flow_storage(&mut fact.value_flow);
            if let Some(value) = &mut fact.static_value {
                compact_static_scalar(value);
            }
        }
        for fact in &mut self.call_argument_values {
            compact_expression_flow_storage(&mut fact.value_flow);
            if let Some(value) = &mut fact.static_value {
                compact_static_scalar(value);
            }
            for field in &mut fact.exact_static_aggregate_fields {
                compact_strings(&mut field.path);
                compact_static_scalar(&mut field.value);
            }
            fact.exact_static_aggregate_fields.shrink_to_fit();
        }
        for fact in &mut self.static_string_maps {
            fact.target.shrink_to_fit();
            for entry in &mut fact.entries {
                entry.key.shrink_to_fit();
                entry.value.shrink_to_fit();
            }
            fact.entries.shrink_to_fit();
        }
        for fact in &mut self.string_compositions {
            for part in &mut fact.parts {
                match part {
                    crate::StringCompositionPart::Literal { value } => value.shrink_to_fit(),
                    crate::StringCompositionPart::Place { place } => place.shrink_to_fit(),
                    crate::StringCompositionPart::PlaceOrLiteral { place, fallback } => {
                        place.shrink_to_fit();
                        fallback.shrink_to_fit();
                    }
                    crate::StringCompositionPart::Call { .. } => {}
                    crate::StringCompositionPart::CallOrLiteral { fallback, .. } => {
                        fallback.shrink_to_fit();
                    }
                }
            }
            fact.parts.shrink_to_fit();
        }
        for fact in &mut self.finite_literal_selections {
            if let Some(target) = &mut fact.target {
                target.shrink_to_fit();
            }
        }
        for fact in &mut self.character_substitutions {
            fact.table.shrink_to_fit();
            for entry in &mut fact.exact_mappings {
                entry.key.shrink_to_fit();
                entry.value.shrink_to_fit();
            }
            fact.exact_mappings.shrink_to_fit();
            if let crate::CharacterSubstitutionDomain::ExactCharacters { characters } = &mut fact.domain {
                compact_strings(characters);
            }
        }
        for fact in &mut self.character_constraints {
            fact.input_place.shrink_to_fit();
            if let CharacterConstraintOutput::Assignment { target } = &mut fact.output {
                target.shrink_to_fit();
            }
            compact_character_constraint_domain(&mut fact.domain);
        }
        for fact in &mut self.guarded_value_filters {
            fact.input_place.shrink_to_fit();
            fact.output_place.shrink_to_fit();
        }
        for fact in &mut self.dynamic_key_filters {
            compact_optional_string(&mut fact.output_place);
            fact.collection_constructor.shrink_to_fit();
            fact.membership_check.shrink_to_fit();
            compact_strings(&mut fact.rejected_exact_values);
        }
        for fact in &mut self.compiler_guards {
            fact.capability.shrink_to_fit();
        }
        for fact in &mut self.runtime_type_narrowings {
            fact.subject.shrink_to_fit();
            fact.type_name.shrink_to_fit();
        }
        for layout in &mut self.aggregate_layouts {
            layout.type_name.shrink_to_fit();
            compact_strings(&mut layout.fields);
        }
        for literal in &mut self.strings {
            literal.text.shrink_to_fit();
            compact_optional_string(&mut literal.static_value);
        }
        for fact in &mut self.branch_conditions {
            if let Some(membership) = &mut fact.membership {
                membership.subject.shrink_to_fit();
                membership.collection.shrink_to_fit();
            }
            if let Some(expression) = &mut fact.expression {
                compact_condition_expression(expression);
            }
        }
        for comment in &mut self.comments {
            comment.text.shrink_to_fit();
        }
        self.defs.shrink_to_fit();
        self.refs.shrink_to_fit();
        self.assignment_values.shrink_to_fit();
        self.call_receivers.shrink_to_fit();
        self.call_argument_values.shrink_to_fit();
        self.static_string_maps.shrink_to_fit();
        self.string_compositions.shrink_to_fit();
        self.finite_literal_selections.shrink_to_fit();
        self.character_substitutions.shrink_to_fit();
        self.character_constraints.shrink_to_fit();
        self.guarded_value_filters.shrink_to_fit();
        self.same_origin_path_constraints.shrink_to_fit();
        self.compiler_guards.shrink_to_fit();
        self.dynamic_key_filters.shrink_to_fit();
        self.runtime_type_narrowings.shrink_to_fit();
        self.branch_conditions.shrink_to_fit();
        self.aggregate_layouts.shrink_to_fit();
        self.strings.shrink_to_fit();
        self.comments.shrink_to_fit();
    }
}

fn compact_character_constraint_domain(domain: &mut CharacterConstraintDomain) {
    match domain {
        CharacterConstraintDomain::AllowOnly {
            classes,
            exact_characters,
        } => {
            classes.shrink_to_fit();
            compact_strings(exact_characters);
        }
        CharacterConstraintDomain::ExcludesExact { characters } => compact_strings(characters),
        CharacterConstraintDomain::ProviderBound {
            factory_call,
            operation_call,
            domain,
        } => {
            factory_call.shrink_to_fit();
            operation_call.shrink_to_fit();
            compact_character_constraint_domain(domain);
        }
    }
}

fn compact_static_scalar(value: &mut StaticScalarValue) {
    if let StaticScalarValue::String(value) = value {
        value.shrink_to_fit();
    }
}

fn compact_condition_expression(expression: &mut ConditionExpressionFact) {
    match expression {
        ConditionExpressionFact::Atom { .. } => {}
        ConditionExpressionFact::Truthy { operand, .. } => compact_condition_operand(operand),
        ConditionExpressionFact::Not { operand, .. } => compact_condition_expression(operand),
        ConditionExpressionFact::All { operands, .. } | ConditionExpressionFact::Any { operands, .. } => {
            for operand in operands.iter_mut() {
                compact_condition_expression(operand);
            }
            operands.shrink_to_fit();
        }
        ConditionExpressionFact::Equality { left, right, .. } => {
            compact_condition_operand(left);
            compact_condition_operand(right);
        }
        ConditionExpressionFact::TypeTest {
            subject, type_name, ..
        } => {
            compact_condition_operand(subject);
            type_name.shrink_to_fit();
        }
        ConditionExpressionFact::Membership {
            subject, collection, ..
        } => {
            compact_condition_operand(subject);
            compact_condition_operand(collection);
        }
    }
}

fn compact_condition_operand(operand: &mut crate::ConditionOperandFact) {
    compact_expression_flow_storage(&mut operand.value_flow);
    compact_optional_string(&mut operand.static_string);
    if let Some(value) = operand.static_value.as_mut() {
        compact_static_scalar(value);
    }
}

fn compact_decl_storage(decl: &mut Decl) {
    decl.name.shrink_to_fit();
    compact_optional_string(&mut decl.qualified_name);
    compact_strings(&mut decl.module_path.segments);
    compact_flow_events(&mut decl.flow_events);
    compact_strings(&mut decl.params);
    for annotations in &mut decl.param_annotations {
        compact_strings(annotations);
    }
    decl.param_annotations.shrink_to_fit();
    for alias in &mut decl.type_aliases {
        alias.name.shrink_to_fit();
        alias.type_name.shrink_to_fit();
    }
    decl.type_aliases.shrink_to_fit();
    compact_strings(&mut decl.bases);
    for write in &mut decl.receiver_field_writes {
        write.target.shrink_to_fit();
        write.source_param_indices.shrink_to_fit();
    }
    decl.receiver_field_writes.shrink_to_fit();
    compact_strings(&mut decl.implicit_receiver_names);
    compact_strings(&mut decl.receiver_state_sources);
    compact_optional_string(&mut decl.return_type);
}

fn compact_flow_event_storage(event: &mut FlowEvent) {
    match event {
        FlowEvent::Call {
            name,
            receiver,
            receiver_types,
            args,
            ..
        } => {
            name.shrink_to_fit();
            compact_optional_string(receiver);
            compact_strings(receiver_types);
            for arg in args.iter_mut() {
                compact_optional_string(&mut arg.name);
                arg.value_text.shrink_to_fit();
                compact_optional_string(&mut arg.place);
                compact_strings(&mut arg.source_names);
            }
            args.shrink_to_fit();
        }
        FlowEvent::Branch {
            condition,
            then_events,
            else_events,
            ..
        } => {
            compact_optional_string(condition);
            compact_flow_events(then_events);
            compact_flow_events(else_events);
        }
        FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
            compact_flow_events(body);
        }
        FlowEvent::Assign {
            target,
            source_name,
            source_call,
            source_call_args,
            source_names,
            ..
        } => {
            target.shrink_to_fit();
            compact_optional_string(source_name);
            compact_optional_string(source_call);
            compact_strings(source_call_args);
            compact_strings(source_names);
        }
        FlowEvent::AggregateAssign {
            target,
            type_name,
            value_flow,
            ..
        } => {
            target.shrink_to_fit();
            compact_optional_string(type_name);
            compact_expression_flow_storage(value_flow);
        }
        FlowEvent::Return {
            value_text,
            value_name,
            value_flow,
            ..
        } => {
            compact_optional_string(value_text);
            compact_optional_string(value_name);
            compact_expression_flow_storage(value_flow);
        }
        FlowEvent::Throw {
            value_name,
            thrown_type,
            ..
        } => {
            compact_optional_string(value_name);
            compact_optional_string(thrown_type);
        }
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            catch_param,
            catch_types,
            ..
        } => {
            compact_flow_events(body);
            compact_flow_events(catch_events);
            compact_flow_events(finally_events);
            compact_optional_string(catch_param);
            compact_strings(catch_types);
        }
        FlowEvent::Break { label, .. } | FlowEvent::Continue { label, .. } => {
            compact_optional_string(label);
        }
        FlowEvent::Yield {
            value_text,
            value_flow,
            ..
        } => {
            compact_optional_string(value_text);
            compact_expression_flow_storage(value_flow);
        }
        FlowEvent::Await { value_name, .. } => compact_optional_string(value_name),
        FlowEvent::Lifecycle { name, transition, .. } => {
            name.shrink_to_fit();
            transition.shrink_to_fit();
        }
    }
}

fn compact_flow_events(events: &mut Vec<FlowEvent>) {
    for event in events.iter_mut() {
        compact_flow_event_storage(event);
    }
    events.shrink_to_fit();
}

fn compact_expression_flow_storage(flow: &mut ExpressionFlow) {
    compact_optional_string(&mut flow.place);
    if let Some(projection) = &mut flow.projection {
        projection.base.shrink_to_fit();
        compact_strings(&mut projection.path);
    }
    compact_strings(&mut flow.source_names);
    flow.call_sites.shrink_to_fit();
    for field in &mut flow.aggregate_fields {
        field.name.shrink_to_fit();
        compact_expression_flow_storage(&mut field.value);
    }
    flow.aggregate_fields.shrink_to_fit();
    for item in &mut flow.tuple_items {
        compact_expression_flow_storage(item);
    }
    flow.tuple_items.shrink_to_fit();
    for spread in &mut flow.spreads {
        compact_expression_flow_storage(spread);
    }
    flow.spreads.shrink_to_fit();
}

fn compact_strings(strings: &mut Vec<String>) {
    for value in strings.iter_mut() {
        value.shrink_to_fit();
    }
    strings.shrink_to_fit();
}

fn compact_optional_string(value: &mut Option<String>) {
    if let Some(value) = value {
        value.shrink_to_fit();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bonsai_common::{FileId, Span};

    fn overallocated(value: &str) -> String {
        let mut text = String::with_capacity(128);
        text.push_str(value);
        text
    }

    #[test]
    fn compact_storage_packs_nested_flow_without_changing_facts() {
        let mut then_events = Vec::with_capacity(32);
        then_events.push(FlowEvent::Assign {
            span: Span::new(FileId::new(0), 1, 2),
            target: overallocated("target"),
            source_name: Some(overallocated("source")),
            source_call: None,
            source_call_args: Vec::with_capacity(16),
            source_names: {
                let mut names = Vec::with_capacity(16);
                names.push(overallocated("source"));
                names
            },
            declares_new_binding: false,
            value_kind: Some(crate::AssignValueKind::Compound),
        });
        let mut events = Vec::with_capacity(32);
        events.push(FlowEvent::Branch {
            span: Span::new(FileId::new(0), 0, 3),
            condition: Some(overallocated("allowed")),
            then_events,
            else_events: Vec::with_capacity(16),
        });
        let expected = events.clone();

        compact_flow_events(&mut events);

        assert_eq!(events, expected);
        assert_eq!(events.capacity(), events.len());
        let FlowEvent::Branch {
            condition,
            then_events,
            else_events,
            ..
        } = &events[0]
        else {
            panic!("branch fixture changed")
        };
        assert_eq!(condition.as_ref().map(String::capacity), Some("allowed".len()));
        assert_eq!(then_events.capacity(), then_events.len());
        assert_eq!(else_events.capacity(), 0);
        let FlowEvent::Assign {
            target,
            source_name,
            source_call_args,
            source_names,
            ..
        } = &then_events[0]
        else {
            panic!("assignment fixture changed")
        };
        assert_eq!(target.capacity(), target.len());
        assert_eq!(source_name.as_ref().map(String::capacity), Some("source".len()));
        assert_eq!(source_call_args.capacity(), 0);
        assert_eq!(source_names.capacity(), source_names.len());
        assert_eq!(source_names[0].capacity(), source_names[0].len());
    }
}
