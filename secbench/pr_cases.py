"""Construct explicitly synthetic PR regressions from pinned upstream snapshots."""
import ast
import contextlib
import copy
import difflib
import io
import os
from pathlib import Path
import shutil
import tempfile
import traceback
import types
import warnings

from .catalog import digest
from .runner import checked_lock, tree_hash, write_json


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError(f"expected exactly one edit anchor: {old[:80]}")
    return text.replace(old,new,1)


def extract_function(text, name, env):
    """Execute only the named function definition, never module initialization."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore",SyntaxWarning)
        tree=ast.parse(text)
    nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name == name]
    if len(nodes) != 1 or nodes[0].decorator_list:
        raise ValueError(f"expected one undecorated function {name}")
    exec(compile(ast.Module(body=nodes,type_ignores=[]),"<isolated-function>","exec"),env)
    return env[name]


def validate_log_reader(original, repaired):
    """Replay a harmless file-write expression through the actual isolated reader."""
    outcomes=[]
    with tempfile.TemporaryDirectory() as td:
        root=Path(td)
        log=root/"train.log"
        marker=root/"marker.txt"
        value={"sample_rate":"40k","if_f0":1,"version":"v2"}
        payload=f"(__import__('pathlib').Path({str(marker)!r}).write_text('executed'), {value!r})[1]"
        for text in (original,repaired):
            env={"os":os,"traceback":traceback,"ast":ast}
            fn=extract_function(text,"change_info_",env)
            log.write_text(repr(value)+"\n",encoding="utf-8")
            normal=fn(str(root/"model.pth"))
            if normal != ("40k","1","v2"):
                raise ValueError("repair changed normal log-reader behavior")
            if marker.exists(): marker.unlink()
            log.write_text(payload+"\n",encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()):
                fn(str(root/"model.pth"))
            outcomes.append(marker.exists())
        if outcomes != [True,False]:
            raise ValueError("log-reader exploit did not distinguish original and repaired")
    return {"level":"isolated_function_replay","original_marker_written":True,
            "repaired_marker_written":False,"normal_behavior_preserved":True,
            "limitations":"Proves code execution from controlled train.log content; does not establish remote upload/reachability in a deployed application."}


def validate_command_builder(original, repaired, utilities):
    """Capture the actual function's process boundary; do not execute a shell."""
    calls=[]
    clean_env={"os":os}
    clean=extract_function(utilities,"clean_path",clean_env)
    for text in (original,repaired):
        captures=[]
        env={"p_label":None,"python_exec":"python","webui_port_subfix":9871,
             "is_share":False,"process_name_subfix":"fixture",
             "check_for_existance":lambda _:None,
             "my_utils":types.SimpleNamespace(clean_path=clean),
             "process_info":lambda *args:"fixture",
             "Popen":lambda args,**kwargs:captures.append((args,kwargs)) or object()}
        fn=extract_function(text,"change_label",env)
        attack="input$(printf INJECTED).list"
        with contextlib.redirect_stdout(io.StringIO()): list(fn(attack))
        if len(captures) != 1: raise ValueError("expected one process invocation")
        args,kwargs=captures[0]
        calls.append((args,kwargs))
        if text == repaired:
            if kwargs.get("shell") is not False or args[3] != attack:
                raise ValueError("repair failed to preserve the untrusted input as one argument")
            if args != ["python","tools/subfix_webui.py","--load_list",attack,
                        "--webui_port","9871","--is_share","False"]:
                raise ValueError("repair changed command arguments")
    if not isinstance(calls[0][0],str) or calls[0][1].get("shell") is not True:
        raise ValueError("original no longer exposes a shell boundary")
    return {"level":"isolated_function_process_boundary","original_shell":True,
            "repaired_shell":False,"argument_preservation_checked":True,
            "limitations":"Popen is intercepted; no actual shell exploit, UI exposure, model stack, or downstream script execution is tested. Existence checking is stubbed; clean_path uses upstream implementation."}


def recipes(data, work):
    by_id={c["id"]:c for c in data["cases"]}
    rvc=by_id["t005"]
    gpt=by_id["t006"]
    rlock=checked_lock(data,rvc,work)
    glock=checked_lock(data,gpt,work)
    rpath="infer-web.py"
    rtext=(Path(rlock["source_dir"])/rpath).read_text(encoding="utf-8")
    rfixed=replace_once(rtext,'info = eval(f.read().strip("\\n").split("\\n")[0].split("\\t")[-1])',
                              'info = __import__("ast").literal_eval(f.read().strip("\\n").split("\\n")[0].split("\\t")[-1])')
    gpath="webui.py"
    gtext=(Path(glock["source_dir"])/gpath).read_text(encoding="utf-8")
    old='cmd = \'"%s" tools/subfix_webui.py --load_list "%s" --webui_port %s --is_share %s\'%(python_exec,path_list,webui_port_subfix,is_share)'
    new='cmd = [python_exec, "tools/subfix_webui.py", "--load_list", path_list, "--webui_port", str(webui_port_subfix), "--is_share", str(is_share)]'
    gfixed=replace_once(gtext,old,new)
    gfixed=replace_once(gfixed,"p_label = Popen(cmd, shell=True)","p_label = Popen(cmd, shell=False)")
    utility=(Path(glock["source_dir"])/"tools/my_utils.py").read_text(encoding="utf-8")
    return [
        {"case":rvc,"lock":rlock,"path":rpath,"function":"change_info_",
         "original":rtext,"repaired":rfixed,"label_id":"GHSL-2025-015",
         "validation":validate_log_reader(rtext,rfixed)},
        {"case":gpt,"lock":glock,"path":gpath,"function":"change_label",
         "original":gtext,"repaired":gfixed,"label_id":"GHSL-2025-048",
         "validation":validate_command_builder(gtext,gfixed,utility)},
    ]


def build(data, work, destination):
    destination=Path(destination).resolve()
    if destination.exists():
        raise ValueError("PR destination already exists; choose a fresh --out directory")
    prepared=recipes(data,work)  # Validate all transformations before writing.
    destination.mkdir(parents=True)
    suite={"schema_version":1,"name":"ghsl-reconstructed-pr-v1","cases":[],
           "status":"constructed_regressions","label_provenance":"Curated from Security Lab reports; fixes authored locally, not upstream patches.",
           "limitations":["Two independent scenarios, six correlated variants, all development cases.",
                           "Both scenarios share the voice-conversion leakage group; no held-out estimate.",
                           "Validation is at the isolated function boundary, not deployed applications.",
                           "Controls are target-specific; other existing vulnerabilities may remain."]}
    validations=[]
    variants=["regression","safe_edit","preexisting"]
    for recipe in prepared:
        original,repaired=recipe["original"],recipe["repaired"]
        function=recipe["function"]
        header=f"def {function}("
        # Add a neutral comment above the function; functionality is unchanged.
        def edit(text):
            return replace_once(text,header,f"# Read and process the selected input.\n{header}")
        for variant in variants:
            identifier=f"p{len(suite['cases'])+1:03}"
            base=repaired if variant != "preexisting" else original
            head=original if variant == "regression" else edit(base)
            if variant != "regression":
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore",SyntaxWarning)
                    if ast.dump(ast.parse(base)) != ast.dump(ast.parse(head)):
                        raise ValueError("control edit changed Python semantics")
            label=copy.deepcopy(next(l for l in recipe["case"]["labels"] if l["id"] == recipe["label_id"]))
            label["evidence_required"].append("Explain why the proposed diff introduces the target relative to the repaired base.")
            case={"id":identifier,"repository":recipe["case"]["repository"],
                  "ref":recipe["lock"]["commit"],"mode":"pr","split":"dev",
                  "leakage_group":"voice-conversion","validation":"function_boundary_checked",
                  "construction":"authored_regression","variant":variant,
                  "target_label_id":label["id"],"labels":[label] if variant == "regression" else [],
                  "control_scope":"target_only","notes":"Full upstream tree; one changed file. Repaired baseline is authored, not an upstream historical commit."}
            suite["cases"].append(case)
            base_dir=destination/"bases"/identifier
            head_dir=destination/"sources"/identifier
            shutil.copytree(recipe["lock"]["source_dir"],base_dir)
            shutil.copytree(recipe["lock"]["source_dir"],head_dir)
            (base_dir/recipe["path"]).write_text(base,encoding="utf-8",newline="\n")
            (head_dir/recipe["path"]).write_text(head,encoding="utf-8",newline="\n")
            diff="".join(difflib.unified_diff(base.splitlines(True),head.splitlines(True),
                                           fromfile="a/"+recipe["path"],tofile="b/"+recipe["path"]))
            patch=destination/"diffs"/(identifier+".patch")
            patch.parent.mkdir(exist_ok=True)
            patch.write_text(diff,encoding="utf-8",newline="\n")
            lock={"case_id":identifier,"repository":case["repository"],"commit":case["ref"],
                  "source_dir":str(head_dir),"base_source_dir":str(base_dir),
                  "tree_sha256":tree_hash(head_dir),"base_tree_sha256":tree_hash(base_dir),
                  "patch_sha256":__import__('hashlib').sha256(diff.encode()).hexdigest()}
            write_json(destination/"locks"/(identifier+".json"),lock)
        validations.append({"repository":recipe["case"]["repository"],"commit":recipe["lock"]["commit"],
                            "target":recipe["label_id"],"validation":recipe["validation"]})
    for case in suite["cases"]:
        lock_path=destination/"locks"/(case["id"]+".json")
        import json
        lock=json.loads(lock_path.read_text())
        lock["catalog_sha256"]=digest(suite)
        write_json(lock_path,lock)
    write_json(destination/"catalog.json",suite)
    write_json(destination/"validation.json",{"catalog_sha256":digest(suite),"scenarios":validations})
    write_json(destination/"freeze.json",{"catalog_sha256":digest(suite),"catalog":suite})
    return suite
