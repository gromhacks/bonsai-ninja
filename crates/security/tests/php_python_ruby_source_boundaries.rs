//! Exact PHP, Python, and Ruby source-boundary coverage.
//!
//! Provider identities stay in rule data. These tests prove the compiler
//! facts used at each boundary and keep same-spelling application code from
//! becoming a source merely because the dependency is present.

use std::path::{Path, PathBuf};

fn rules_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("security-patterns")
}

fn workspace(path: &str, source: &str) -> bonsai_workspace::Workspace {
    let ws = bonsai_workspace::Workspace::new(bonsai_adapters::all_languages_registry());
    ws.vfs().write(path, source);
    ws
}

fn source_ids(ws: &bonsai_workspace::Workspace) -> Vec<String> {
    let pack = bonsai_security::load_rulepack(&rules_root()).expect("load rulepack");
    bonsai_security::source_inventory(ws, &pack, Default::default())
        .expect("source inventory")
        .into_iter()
        .map(|source| source.rule_id)
        .collect()
}

#[test]
fn php_static_server_keys_are_field_precise_sources() {
    let positive = workspace(
        "index.php",
        r#"<?php
function run() { system($_SERVER["HTTP_HOST"]); }
"#,
    );
    let ids = source_ids(&positive);
    assert!(
        ids.iter().any(|id| id == "php.source.superglobal_server"),
        "static client-controlled server key must match: {ids:#?}; index={:#?}",
        positive.db().global_index()
    );

    let negative = workspace(
        "index.php",
        r#"<?php
function run() { system($_SERVER["SERVER_SOFTWARE"]); }
"#,
    );
    let ids = source_ids(&negative);
    assert!(
        ids.iter().all(|id| id != "php.source.superglobal_server"),
        "server process metadata must not become HTTP input: {ids:#?}"
    );
}

#[test]
fn php_bref_interface_and_slim_route_callback_sources_are_exact() {
    let bref = workspace(
        "Handler.php",
        r#"<?php
use Bref\Event\Handler;
use Bref\Context\Context;
final class FunctionHandler implements Handler {
  public function handle($payload, Context $context): mixed { return system($payload); }
}
"#,
    );
    let ids = source_ids(&bref);
    assert!(
        ids.iter().any(|id| id == "php.source.bref_handler_handle"),
        "Bref interface ancestry must own parameter zero: {ids:#?}; index={:#?}",
        bref.db().global_index()
    );

    let slim = workspace(
        "routes.php",
        r#"<?php
use Slim\Factory\AppFactory;
$app = AppFactory::create();
$app->get('/users/{id}', function ($request, $response, array $route_values) {
  return system($route_values['id']);
});
"#,
    );
    let ids = source_ids(&slim);
    assert!(
        ids.iter().any(|id| id == "php.source.slim_route_args"),
        "typed Slim route callback parameter two must be a source: {ids:#?}; index={:#?}",
        slim.db().global_index()
    );

    let collision = workspace(
        "routes.php",
        r#"<?php
use Slim\Factory\AppFactory;
$cache = new LocalCache();
$cache->get('/users/{id}', function ($left, $right, array $options) { return system($options['id']); });
"#,
    );
    let ids = source_ids(&collision);
    assert!(
        ids.iter().all(|id| id != "php.source.slim_route_args"),
        "same-named application method must not become a Slim source: {ids:#?}"
    );
}

#[test]
fn ruby_job_ancestry_and_route_callback_sources_are_exact() {
    let jobs = workspace(
        "jobs.rb",
        r#"
require "active_job"
require "shoryuken"
class ApplicationJob < ActiveJob::Base; end
class ImportJob < ApplicationJob
  def perform(payload); system(payload); end
end
class QueueWorker
  include Shoryuken::Worker
  def perform(message, body); system(body); end
end
"#,
    );
    let ids = source_ids(&jobs);
    for expected in [
        "ruby.source.activejob_perform_args",
        "ruby.source.shoryuken_perform_body_param",
    ] {
        assert!(
            ids.iter().any(|id| id == expected),
            "missing Ruby job boundary {expected}: {ids:#?}; index={:#?}",
            jobs.db().global_index()
        );
    }

    let roda = workspace(
        "app.rb",
        r#"
require "roda"
class App < Roda
  route do |request|
    system(request.params["cmd"])
  end
end
"#,
    );
    let ids = source_ids(&roda);
    assert!(
        ids.iter().any(|id| id == "ruby.source.roda_route_request"),
        "Roda route block parameter must be an exact source: {ids:#?}; index={:#?}",
        roda.db().global_index()
    );

    let collision = workspace(
        "app.rb",
        r#"
require "roda"
class App < Roda
  configure do |request|
    system(request.params)
  end
end
"#,
    );
    let ids = source_ids(&collision);
    assert!(
        ids.iter().all(|id| id != "ruby.source.roda_route_request"),
        "non-route block must not become request input: {ids:#?}"
    );
}

#[test]
fn python_celery_bound_and_unbound_task_parameters_are_exact() {
    let tasks = workspace(
        "tasks.py",
        r#"from celery import Celery, shared_task
from celery import shared_task as job
app = Celery("jobs")

@shared_task
def shared_unbound(payload):
    return payload

@shared_task(bind=True)
def shared_bound(self, payload):
    return payload

@shared_task(bind=False)
def shared_explicit_unbound(payload):
    return payload

@job(bind=True)
def shared_aliased_bound(self, payload):
    return payload

@app.task
def app_unbound(payload):
    return payload

@app.task(bind=True)
def app_bound(self, payload):
    return payload

@app.task(bind=False)
def app_explicit_unbound(payload):
    return payload
"#,
    );
    let ids = source_ids(&tasks);
    for expected in [
        "python.celery.shared_task_param",
        "python.celery.shared_task_explicit_unbound_param",
        "python.celery.shared_task_bound_param",
        "python.celery.app_task_param",
        "python.celery.app_task_explicit_unbound_param",
        "python.celery.app_task_bound_param",
    ] {
        assert!(
            ids.iter().any(|id| id == expected),
            "missing exact Celery boundary {expected}: {ids:#?}"
        );
    }

    let collision = workspace(
        "tasks.py",
        r#"from celery import Celery
other = LocalRegistry()

@other.task
def helper(payload):
    return payload
"#,
    );
    let ids = source_ids(&collision);
    assert!(
        ids.iter().all(|id| !id.starts_with("python.celery.")),
        "a same-named application decorator must not become a Celery boundary: {ids:#?}"
    );

    let dynamic = workspace(
        "tasks.py",
        r#"from celery import Celery, shared_task
app = Celery("jobs")

@shared_task(bind=runtime_flag)
def shared_unknown(first, payload):
    return payload

@app.task(bind=runtime_flag)
def app_unknown(first, payload):
    return payload
"#,
    );
    let ids = source_ids(&dynamic);
    assert!(
        ids.iter().all(|id| !id.starts_with("python.celery.")),
        "a runtime-unknown bound signature must fail closed: {ids:#?}"
    );
}

#[test]
fn php_python_and_ruby_boundaries_seed_the_production_idg() {
    let pack = bonsai_security::load_rulepack(&rules_root()).expect("load rulepack");
    let cases = [
        (
            workspace(
                "Handler.php",
                r#"<?php
use Bref\Event\Handler;
use Bref\Context\Context;
final class FunctionHandler implements Handler {
  public function handle($payload, Context $context): mixed { return system($payload); }
}
"#,
            ),
            "php.source.bref_handler_handle",
        ),
        (
            workspace(
                "routes.php",
                r#"<?php
use Slim\Factory\AppFactory;
$app = AppFactory::create();
$app->get('/run/{cmd}', function ($request, $response, array $route_values) {
  return system($route_values['cmd']);
});
"#,
            ),
            "php.source.slim_route_args",
        ),
        (
            workspace(
                "tasks.py",
                r#"from celery import shared_task
import os
@shared_task(bind=True)
def process(self, payload):
    return os.system(payload)
"#,
            ),
            "python.celery.shared_task_bound_param",
        ),
        (
            workspace(
                "tasks.py",
                r#"from celery import Celery
import os
worker = Celery("jobs")
@worker.task(bind=True)
def process(self, payload):
    return os.system(payload)
"#,
            ),
            "python.celery.app_task_bound_param",
        ),
        (
            workspace(
                "job.rb",
                r#"require "sidekiq"
class ImportJob
  include Sidekiq::Job
  def perform(payload)
    system(payload)
  end
end
"#,
            ),
            "ruby.source.sidekiq_perform_args",
        ),
        (
            workspace(
                "app.rb",
                r#"require "roda"
class App < Roda
  route do |request|
    system(request.params["cmd"])
  end
end
"#,
            ),
            "ruby.source.roda_route_request",
        ),
    ];

    for (ws, expected) in cases {
        let report = bonsai_security::run_taint_analysis(&ws, &pack, Default::default())
            .unwrap_or_else(|error| panic!("taint analysis for {expected}: {error}"));
        let actual = report
            .findings
            .iter()
            .map(|finding| finding.finding.source.rule_id.as_str())
            .collect::<Vec<_>>();
        assert!(
            actual.contains(&expected),
            "{expected} must seed a complete source-to-sink IDG path: {actual:#?}"
        );
    }
}

#[test]
fn same_spelling_ruby_callback_does_not_seed_the_production_idg() {
    let pack = bonsai_security::load_rulepack(&rules_root()).expect("load rulepack");
    let ws = workspace(
        "app.rb",
        r#"require "roda"
class App < Roda
  configure do |request|
    system(request.params["cmd"])
  end
end
"#,
    );
    let report = bonsai_security::run_taint_analysis(&ws, &pack, Default::default())
        .expect("collision-negative taint analysis");
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.finding.source.rule_id != "ruby.source.roda_route_request"),
        "a non-route callback must not acquire the Roda request boundary: {:#?}",
        report.findings
    );
}
