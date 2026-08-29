use bonsai_lang_api::RefKind;

#[test]
fn decorator_static_boolean_keywords_are_exact_compiler_facts() {
    let ws = bonsai_testkit::workspace_with(
        vec![std::sync::Arc::new(bonsai_lang_python::PythonAdapter::new())],
        &[(
            "tasks.py",
            r#"from celery import Celery as CeleryFactory, shared_task
from celery import shared_task as job

worker = CeleryFactory("jobs")
app = CeleryFactory("jobs")
local = LocalRegistry()

@shared_task(bind=True)
def bound(self, payload):
    return payload

@app.task(ignore_result=True, bind=False)
def unbound(payload):
    return payload

@shared_task(bind=runtime_flag)
def dynamic(payload):
    return payload

@job(bind=True)
def aliased(self, payload):
    return payload

@worker.task(bind=True)
def call_result_receiver(self, payload):
    return payload

@local.task(bind=True)
def local_collision(self, payload):
    return payload
"#,
        )],
    );
    let file = ws.vfs().all_files().into_iter().next().expect("file id");
    let index = ws.db().decl_index(file).expect("declaration index");
    let decorators = index
        .refs
        .iter()
        .filter(|reference| reference.kind == RefKind::Decorator)
        .map(|reference| reference.name.as_str())
        .collect::<Vec<_>>();

    assert!(decorators.contains(&"shared_task.bind=true"), "{decorators:#?}");
    assert!(decorators.contains(&"shared_task.bind"), "{decorators:#?}");
    assert!(decorators.contains(&"celery.shared_task"), "{decorators:#?}");
    assert!(
        decorators.contains(&"celery.shared_task.bind=true"),
        "{decorators:#?}"
    );
    assert!(
        decorators.contains(&"celery.Celery.task.bind=true"),
        "{decorators:#?}"
    );
    assert_eq!(
        decorators
            .iter()
            .filter(|name| **name == "celery.Celery.task.bind=true")
            .count(),
        1,
        "an unrelated call result must not acquire the imported Celery identity: {decorators:#?}"
    );
    assert!(
        decorators.contains(&"app.task.ignore_result=true"),
        "{decorators:#?}"
    );
    assert!(decorators.contains(&"app.task.ignore_result"), "{decorators:#?}");
    assert!(decorators.contains(&"app.task.bind=false"), "{decorators:#?}");
    assert!(decorators.contains(&"app.task.bind"), "{decorators:#?}");
    assert!(
        decorators
            .iter()
            .all(|name| *name != "shared_task.bind=runtime_flag"),
        "dynamic keyword expressions must not become static facts: {decorators:#?}"
    );
    assert_eq!(
        decorators
            .iter()
            .filter(|name| **name == "shared_task.bind")
            .count(),
        2,
        "the raw static and runtime-unknown keyword forms retain exact presence: {decorators:#?}"
    );
}
