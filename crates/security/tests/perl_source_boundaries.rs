//! Perl source-boundary coverage from compiler facts through rule matching
//! and the sparse-IDG taint closure.
//!
//! Every positive uses the idiomatic package-qualified constructor plus an
//! arrow method. Every collision twin imports the same external module but
//! invokes a same-named method on a compiler-distinct local receiver.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn rules_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("security-patterns")
}

fn workspace(source: &str) -> bonsai_workspace::Workspace {
    let ws = bonsai_workspace::Workspace::new(bonsai_adapters::all_languages_registry());
    ws.vfs().write("boundaries.pl", source);
    ws
}

fn source_ids(source: &str) -> BTreeSet<String> {
    let ws = workspace(source);
    let pack = bonsai_security::load_rulepack(&rules_root()).expect("load rulepack");
    assert!(
        pack.find_rule_by_id("perl.source.bcm2835_gpio_level").is_some(),
        "new Perl source rules must be loaded"
    );
    bonsai_security::source_inventory(&ws, &pack, bonsai_security::SecurityInventoryOptions::default())
        .expect("source inventory")
        .into_iter()
        .map(|source| source.rule_id)
        .collect()
}

fn taint_source_ids(source: &str) -> BTreeSet<String> {
    let ws = workspace(source);
    let pack = bonsai_security::load_rulepack(&rules_root()).expect("load rulepack");
    bonsai_security::run_taint_analysis(&ws, &pack, Default::default())
        .expect("taint analysis")
        .findings
        .into_iter()
        .map(|finding| finding.finding.source.rule_id)
        .collect()
}

#[test]
fn exact_perl_database_queue_cloud_and_physical_sources_match() {
    let source = r#"
use DBI;
use Net::AMQP::RabbitMQ;
use Kafka::Consumer;
use Amazon::S3::Thin;
use Amazon::S3::Lite;
use Device::SerialPort;
use Device::BCM2835;

sub boundaries {
    my ($connection) = @_;
    my $argv_value = $ARGV[0];
    my $dbh = DBI->connect('dbi:SQLite:dbname=app.db');
    my $sth = $dbh->prepare('select name from users');
    my $row = $sth->fetchrow_arrayref();
    my $selected = $dbh->selectrow_hashref('select name from users');

    my $rabbit = Net::AMQP::RabbitMQ->new();
    my $delivery = $rabbit->recv(5);
    my $consumer = Kafka::Consumer->new(Connection => $connection);
    my $messages = $consumer->fetch('events', 0, 0, 1048576);

    my $thin = Amazon::S3::Thin->new({ aws_access_key_id => 'key' });
    my $thin_object = $thin->get_object('uploads', 'incoming.json');
    my $lite = Amazon::S3::Lite->new(access_key => 'key', secret_key => 'secret');
    my $lite_object = $lite->get_object('uploads', 'incoming.json');

    my $port = Device::SerialPort->new('/dev/ttyUSB0');
    my ($count, $bytes) = $port->read(128);
    my $gpio = Device::BCM2835::gpio_lev(7);
    return ($row, $selected, $delivery, $messages, $thin_object, $lite_object, $bytes, $gpio);
}
"#;
    let ids = source_ids(source);
    assert!(
        ids.contains("perl.source.argv"),
        "baseline Perl source matching failed; got {ids:?}"
    );
    for expected in [
        "perl.source.dbi_statement_fetchrow",
        "perl.source.dbi_database_select_rows",
        "perl.source.rabbitmq_delivery",
        "perl.source.kafka_consumer_fetch",
        "perl.source.amazon_s3_thin_get_object",
        "perl.source.amazon_s3_lite_get_object",
        "perl.source.device_serialport_read",
        "perl.source.bcm2835_gpio_level",
    ] {
        assert!(
            ids.contains(expected),
            "missing exact Perl source {expected}; got {ids:?}"
        );
    }
}

#[test]
fn same_named_local_receivers_do_not_cross_external_source_boundaries() {
    let source = r#"
use DBI;
use Net::AMQP::RabbitMQ;
use Kafka::Consumer;
use Amazon::S3::Thin;
use Amazon::S3::Lite;
use Device::SerialPort;

package LocalThing;
sub new { bless {}, shift }
sub prepare { LocalThing->new() }
sub fetchrow_arrayref { ['local'] }
sub selectrow_hashref { { name => 'local' } }
sub recv { { body => 'local' } }
sub fetch { [] }
sub get_object { 'local' }
sub read { (5, 'local') }

package main;
sub clean {
    my $local = LocalThing->new();
    my $statement = $local->prepare('local');
    return (
        $statement->fetchrow_arrayref(),
        $local->selectrow_hashref('local'),
        $local->recv(),
        $local->fetch('events', 0, 0, 1048576),
        $local->get_object('uploads', 'incoming.json'),
        $local->read(128),
    );
}
"#;
    let ids = source_ids(source);
    let forbidden = ids
        .iter()
        .filter(|id| {
            id.starts_with("perl.source.dbi_")
                || id.starts_with("perl.source.rabbitmq_")
                || id.starts_with("perl.source.kafka_")
                || id.starts_with("perl.source.amazon_s3_")
                || id.as_str() == "perl.source.device_serialport_read"
        })
        .cloned()
        .collect::<Vec<_>>();
    assert!(
        forbidden.is_empty(),
        "local receiver collisions must remain clean: {forbidden:?}"
    );
}

#[test]
fn representative_perl_boundary_results_reach_a_real_sink() {
    let source = r#"
use DBI;
use Net::AMQP::RabbitMQ;
use Amazon::S3::Thin;
use Device::BCM2835;

sub database_flow {
    my $dbh = DBI->connect('dbi:SQLite:dbname=app.db');
    my $sth = $dbh->prepare('select command from jobs');
    my $row = $sth->fetchrow_arrayref();
    system($row);
}

sub queue_flow {
    my $rabbit = Net::AMQP::RabbitMQ->new();
    my $delivery = $rabbit->recv();
    system($delivery);
}

sub cloud_flow {
    my $client = Amazon::S3::Thin->new({ aws_access_key_id => 'key' });
    my $response = $client->get_object('uploads', 'command.txt');
    system($response);
}

sub physical_flow {
    my $level = Device::BCM2835::gpio_lev(7);
    system($level);
}
"#;
    let ids = taint_source_ids(source);
    for expected in [
        "perl.source.dbi_statement_fetchrow",
        "perl.source.rabbitmq_delivery",
        "perl.source.amazon_s3_thin_get_object",
        "perl.source.bcm2835_gpio_level",
    ] {
        assert!(
            ids.contains(expected),
            "Perl source {expected} must reach system(); got {ids:?}"
        );
    }
}

#[test]
fn interpolated_heredoc_reaches_html_sink_while_literal_heredoc_stays_clean() {
    let pack = bonsai_security::load_rulepack(&rules_root()).expect("load rulepack");
    let positive = workspace(
        r#"
use Mojo::Base 'Mojolicious::Controller', -signatures;
sub index ($self) {
    my $value = $self->param('value');
    my $page = <<"HTML";
<p>$value</p>
HTML
    $self->render(text => $page, format => 'html');
}

"#,
    );
    let report = bonsai_security::run_taint_analysis(&positive, &pack, Default::default())
        .expect("interpolated heredoc taint analysis");
    assert!(
        report.findings.iter().any(|finding| {
            finding.finding.source.rule_id == "perl.source.mojolicious_req_param"
                && finding.finding.sink.rule_id == "perl.xss.mojolicious_render"
        }),
        "the compiler-proven heredoc interpolation must reach the HTML sink: {:#?}",
        report.findings
    );

    let collision = workspace(
        r#"
use Mojo::Base 'Mojolicious::Controller', -signatures;
sub index ($self) {
    my $value = $self->param('value');
    my $page = <<'HTML';
<p>$value</p>
HTML
    $self->render(text => $page, format => 'html');
}
"#,
    );
    let report = bonsai_security::run_taint_analysis(&collision, &pack, Default::default())
        .expect("literal heredoc collision analysis");
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.finding.sink.rule_id != "perl.xss.mojolicious_render"),
        "a single-quoted heredoc must not interpolate the same-spelled scalar: {:#?}",
        report.findings
    );

    let plain_text = workspace(
        r#"
use Mojo::Base 'Mojolicious::Controller', -signatures;
sub index ($self) {
    my $value = $self->param('value');
    $self->render(text => $value);
}
"#,
    );
    let report = bonsai_security::run_taint_analysis(&plain_text, &pack, Default::default())
        .expect("plain text response analysis");
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.finding.sink.rule_id != "perl.xss.mojolicious_render"),
        "a plain text response without an explicit HTML format is not an XSS sink: {:#?}",
        report.findings
    );
}

#[test]
fn finite_literal_hash_selection_cleans_sql_identifier_while_dynamic_value_remains_tainted() {
    let pack = bonsai_security::load_rulepack(&rules_root()).expect("load rulepack");
    let safe = workspace(
        r#"
use Mojo::Base 'Mojolicious::Controller', -signatures;
my %COLUMNS = (name => 'name', created => 'created');
sub index ($self) {
    my $sort = $self->param('sort');
    my $column = $COLUMNS{$sort} // 'name';
    $self->selectall_arrayref("SELECT id FROM users ORDER BY $column");
}
"#,
    );
    let report = bonsai_security::run_taint_analysis(&safe, &pack, Default::default())
        .expect("finite literal selection analysis");
    assert!(
        report.findings.iter().all(|finding| {
            finding.finding.sink.rule_id != "perl.sqli.dbi_selectall"
                || finding.finding.status == bonsai_security::FindingStatus::Sanitized
        }),
        "a finite static hash chooses a literal, not the untrusted key: {:#?}",
        report.findings
    );

    let unsafe_workspace = workspace(
        r#"
use Mojo::Base 'Mojolicious::Controller', -signatures;
sub index ($self) {
    my $sort = $self->param('sort');
    $self->selectall_arrayref("SELECT id FROM users ORDER BY $sort");
}
"#,
    );
    let report = bonsai_security::run_taint_analysis(&unsafe_workspace, &pack, Default::default())
        .expect("dynamic SQL identifier analysis");
    assert!(
        report.findings.iter().any(|finding| {
            finding.finding.sink.rule_id == "perl.sqli.dbi_selectall"
                && finding.finding.status == bonsai_security::FindingStatus::Unsanitized
        }),
        "a dynamic identifier must remain tainted: {:#?}",
        report.findings
    );
}

#[test]
fn global_safe_character_deletion_cleans_the_mutated_receiver_before_a_sink() {
    let ws = workspace(
        r#"
sub main {
    my $value = $ARGV[0];
    $value =~ s/[^A-Za-z0-9_-]//g;
    system($value);
}
"#,
    );
    let pack = bonsai_security::load_rulepack(&rules_root()).expect("load rulepack");
    let sanitizer_matches = bonsai_security::sanitizer_inventory(
        &ws,
        &pack,
        bonsai_security::SecurityInventoryOptions::default(),
    )
    .expect("sanitizer inventory");
    let sanitizer = sanitizer_matches
        .iter()
        .find(|matched| matched.rule_id == "perl.sanitizer.substitution_char_allowlist")
        .expect("safe substitution compiler fact must match its sanitizer rule");
    let file = ws.vfs().all_files()[0];
    let index = ws.db().decl_index(file).expect("Perl declaration index");
    let call_span = index
        .defs
        .iter()
        .find(|decl| decl.name == "main")
        .and_then(|decl| {
            decl.flow_events.iter().find_map(|event| match event {
                bonsai_lang_api::FlowEvent::Call { span, name, .. } if name == "s" => Some(*span),
                _ => None,
            })
        })
        .expect("substitution call fact");
    assert!(
        sanitizer.span == call_span,
        "matcher and transfer must share one exact call span: match={:?} call={call_span:?}",
        sanitizer.span
    );
    let report = bonsai_security::run_taint_analysis(&ws, &pack, Default::default()).expect("taint analysis");
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.finding.sink.rule_id != "perl.cmdi.system"),
        "matcher-approved in-place allowlist deletion must clean the receiver: {:#?}",
        report.findings
    );
}

#[test]
fn ordinary_substitution_does_not_clean_the_mutated_receiver() {
    let ws = workspace(
        r#"
sub main {
    my $value = $ARGV[0];
    $value =~ s/foo/bar/g;
    system($value);
}
"#,
    );
    let pack = bonsai_security::load_rulepack(&rules_root()).expect("load rulepack");
    let report = bonsai_security::run_taint_analysis(&ws, &pack, Default::default()).expect("taint analysis");
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.finding.sink.rule_id == "perl.cmdi.system"),
        "ordinary substitution must remain taint preserving: {:#?}",
        report.findings
    );
}

#[test]
fn unsafe_retained_class_does_not_clean_the_mutated_receiver() {
    let ws = workspace(
        r#"
sub main {
    my $value = $ARGV[0];
    $value =~ s/[^<]//g;
    system($value);
}
"#,
    );
    let pack = bonsai_security::load_rulepack(&rules_root()).expect("load rulepack");
    let report = bonsai_security::run_taint_analysis(&ws, &pack, Default::default()).expect("taint analysis");
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.finding.sink.rule_id == "perl.cmdi.system"),
        "an unsafe retained alphabet must remain taint preserving: {:#?}",
        report.findings
    );
}
