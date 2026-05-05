//! P1.3: Ruby `module_function` recognition. The bare keyword form
//! flips the surrounding scope to a Public-equivalent (the public
//! module-level half of `module_function`'s dual semantics); the
//! `module_function :name` argument form tags the named method
//! Public.

use bonsai_db::AnalyzerDb;
use bonsai_lang_api::{LanguageRegistry, Visibility};
use bonsai_vfs::Vfs;
use std::sync::Arc;

fn db_with(source: &str) -> AnalyzerDb {
    let vfs = Arc::new(Vfs::new());
    vfs.write("a.rb".to_string(), Arc::<str>::from(source));
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_ruby::RubyAdapter::new()));
    let db = AnalyzerDb::new(vfs, registry);
    for f in db.vfs().all_files() {
        let _ = db.decl_index(f);
    }
    db
}

fn visibility_of(db: &AnalyzerDb, name: &str) -> Visibility {
    let g = db.global_index();
    g.find_by_name(name)
        .iter()
        .find_map(|s| g.decl_of(*s).cloned())
        .map(|d| d.visibility)
        .unwrap_or(Visibility::Public)
}

#[test]
fn module_function_with_symbol_arg_tags_named_method_public() {
    // The convention here is: `private` flips the scope to private,
    // but `module_function :foo` overrides the scope to mark `foo`
    // Public regardless of the surrounding region.
    let src = r#"
module Util
  private

  def helper(x)
    x
  end

  def foo(x)
    helper(x)
  end

  module_function :foo
end
"#;
    let db = db_with(src);
    assert_eq!(
        visibility_of(&db, "foo"),
        Visibility::Public,
        "module_function :foo must override the surrounding `private` scope"
    );
    assert_eq!(
        visibility_of(&db, "helper"),
        Visibility::Private,
        "helper, untagged, picks up the surrounding `private` scope"
    );
}

#[test]
fn module_function_bare_form_flips_scope_to_public() {
    // `module_function` with no args flips the dual-mode (private
    // instance, public module-level) for subsequent defs. Resolver
    // cares about the public module-level half.
    let src = r#"
module Util
  private

  def helper(x)
    x
  end

  module_function

  def foo(x)
    helper(x)
  end
end
"#;
    let db = db_with(src);
    assert_eq!(
        visibility_of(&db, "helper"),
        Visibility::Private,
        "before module_function, helper is in the private scope"
    );
    assert_eq!(
        visibility_of(&db, "foo"),
        Visibility::Public,
        "module_function flips the scope; foo declared after is Public"
    );
}
