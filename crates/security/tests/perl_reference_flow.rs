use bonsai_security::{run_taint_analysis, TaintAnalysisOptions};
use bonsai_workspace::Workspace;
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn rules_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("security-patterns")
}

fn analyze(clean_reference: bool) -> bonsai_security::TaintAnalysisReport {
    let reference_setup = if clean_reference {
        "my @selected = ('id');\n    my @ignored = split /,/, $raw;"
    } else {
        "my @selected = split /,/, $raw;"
    };
    let source = format!(
        r#"package App::Controller::Sort;
use Mojo::Base 'Mojolicious::Controller', -signatures;
use DBI;

sub ordered ($keys) {{
    my $clause = join ', ', @$keys;
    return $DBH->selectall_arrayref("SELECT id FROM users ORDER BY $clause");
}}

sub index ($self) {{
    my $raw = $self->param('sort') // 'id';
    {reference_setup}
    return ordered(\@selected);
}}
"#
    );
    let workspace = Workspace::new(bonsai_adapters::all_languages_registry());
    workspace.vfs().write("lib/Sort.pm", Arc::<str>::from(source));
    let pack = bonsai_security::load_rulepack(&rules_root()).expect("load source-controlled rulepack");
    run_taint_analysis(&workspace, &pack, TaintAnalysisOptions::default())
        .expect("run Perl reference-flow taint analysis")
}

#[test]
fn taint_crosses_array_reference_construction_and_dereference() {
    let report = analyze(false);
    assert!(
        report.findings.iter().any(|finding| {
            finding.finding.source.rule_id == "perl.source.mojolicious_req_param"
                && finding.finding.sink.rule_id == "perl.sqli.dbi_selectall"
        }),
        r"the exact \@array -> @$scalar relation must survive the call boundary: {:#?}",
        report.findings
    );
}

#[test]
fn a_clean_referent_does_not_inherit_taint_from_a_sibling_array() {
    let report = analyze(true);
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.finding.sink.rule_id != "perl.sqli.dbi_selectall"),
        "reference lowering must preserve referent identity instead of tainting every array: {:#?}",
        report.findings
    );
}

fn analyze_collection_selection(callback: &str) -> bonsai_security::TaintAnalysisReport {
    let workspace = Workspace::new(bonsai_adapters::all_languages_registry());
    workspace.vfs().write(
        "lib/App/Controller/Orders.pm",
        Arc::<str>::from(
            r#"package App::Controller::Orders;
use Mojo::Base 'Mojolicious::Controller', -signatures;
use App::Sort;
sub index ($self) {
    my $raw = $self->param('sort') // 'id';
    my @keys = split /,/, $raw;
    return App::Sort::ordered(\@keys);
}
"#,
        ),
    );
    workspace.vfs().write(
        "lib/App/Sort.pm",
        Arc::<str>::from(format!(
            r#"package App::Sort;
use App::Repo;
my %SORTABLE = (total => 'total', created_at => 'created_at', id => 'id');
sub ordered {{
    my ($keys) = @_;
    my @selected = {callback};
    @selected = ('id') unless @selected;
    return App::Repo::list_orders(join(', ', @selected));
}}
"#
        )),
    );
    workspace.vfs().write(
        "lib/App/Repo.pm",
        Arc::<str>::from(
            r#"package App::Repo;
our $DBH;
sub list_orders {
    my ($clause) = @_;
    return $DBH->selectall_arrayref("SELECT id FROM orders ORDER BY $clause");
}
"#,
        ),
    );
    let pack = bonsai_security::load_rulepack(&rules_root()).expect("load source-controlled rulepack");
    run_taint_analysis(&workspace, &pack, TaintAnalysisOptions::default())
        .expect("run Perl finite collection-selection analysis")
}

#[test]
fn finite_literal_map_over_array_reference_breaks_taint_across_files() {
    let safe = analyze_collection_selection("grep { defined } map { $SORTABLE{$_} } @$keys");
    assert!(
        safe.findings
            .iter()
            .all(|finding| finding.finding.sink.rule_id != "perl.sqli.dbi_selectall"),
        "a map/grep selection from an unmodified finite literal hash must break key taint: {:#?}",
        safe.findings
    );

    let unsafe_report = analyze_collection_selection("map { $SORTABLE{$_} . $_ } @$keys");
    assert!(
        unsafe_report.findings.iter().any(|finding| {
            finding.finding.source.rule_id == "perl.source.mojolicious_req_param"
                && finding.finding.sink.rule_id == "perl.sqli.dbi_selectall"
                && finding.finding.status == bonsai_security::FindingStatus::Unsanitized
        }),
        "a map callback that emits the caller-controlled key must remain tainted: {:#?}",
        unsafe_report.findings
    );
}
