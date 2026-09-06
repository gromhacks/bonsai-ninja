//! Language-neutral argument/formal mapping over adapter-owned names.

/// Map an explicit positional argument past an implicitly supplied receiver.
/// Pass `None` when the receiver is itself an explicit argument.
#[must_use]
pub fn explicit_argument_parameter_index(argument: usize, receiver: Option<usize>) -> usize {
    match receiver {
        Some(receiver) if argument >= receiver => argument.saturating_add(1),
        _ => argument,
    }
}

/// Find an adapter-normalized named argument's formal, excluding an implicit
/// receiver. Labels not represented in the formal inventory return `None`;
/// callers can then use the explicit positional mapping.
pub fn named_argument_parameter_index<'a>(
    name: &str,
    parameters: impl IntoIterator<Item = &'a str>,
    receiver: Option<usize>,
) -> Option<usize> {
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    parameters
        .into_iter()
        .enumerate()
        .find(|(index, parameter)| Some(*index) != receiver && parameter.trim() == name)
        .map(|(index, _)| index)
}

/// Recover an explicit actual slot from its exact formal index. This uses
/// the same named/positional binding contract as IDG stitching, including
/// positional labels that are not represented in the formal inventory.
pub fn argument_index_for_parameter<'a>(
    parameter: usize,
    arguments: impl IntoIterator<Item = Option<&'a str>>,
    parameters: &[String],
    receiver: Option<usize>,
) -> Option<usize> {
    arguments.into_iter().enumerate().find_map(|(index, name)| {
        let formal = name
            .and_then(|name| {
                named_argument_parameter_index(name, parameters.iter().map(String::as_str), receiver)
            })
            .unwrap_or_else(|| explicit_argument_parameter_index(index, receiver));
        (formal == parameter).then_some(index)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_arguments_skip_only_the_supplied_receiver() {
        for receiver in [None, Some(0), Some(1), Some(2)] {
            let expected: Vec<_> = (0..4).filter(|index| Some(*index) != receiver).take(3).collect();
            for (argument, parameter) in expected.into_iter().enumerate() {
                assert_eq!(explicit_argument_parameter_index(argument, receiver), parameter);
            }
        }
    }

    #[test]
    fn named_arguments_preserve_exact_names_and_exclude_the_receiver() {
        let params = ["self", "unused", "callback"];
        assert_eq!(
            named_argument_parameter_index("callback", params, Some(0)),
            Some(2)
        );
        assert_eq!(named_argument_parameter_index("self", params, Some(0)), None);
        assert_eq!(named_argument_parameter_index("Callback", params, Some(0)), None);
        assert_eq!(named_argument_parameter_index("", params, None), None);
    }

    #[test]
    fn reverse_binding_distinguishes_receiver_and_reordered_named_arguments() {
        let params = ["self", "first", "last"].map(str::to_owned);
        let args = [Some("last"), Some("first")];
        assert_eq!(argument_index_for_parameter(0, args, &params, Some(0)), None);
        assert_eq!(argument_index_for_parameter(1, args, &params, Some(0)), Some(1));
        assert_eq!(argument_index_for_parameter(2, args, &params, Some(0)), Some(0));
        assert_eq!(argument_index_for_parameter(1, [None], &params, Some(0)), Some(0));
    }
}
