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
}
