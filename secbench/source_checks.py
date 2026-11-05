"""Locate advisory-related symbols. Presence is not proof of exploitability."""
import hashlib
from pathlib import Path

from .catalog import digest
from .runner import checked_lock


def anchors():
    checks = {}

    def add(year, number, pattern, text):
        checks[f"GHSL-{year}-{number:03}"] = (pattern, text)

    add(2023,232,"packages/server/src/index.ts","/api/v1/openai-assistants-file")
    add(2023,234,"packages/server/src/index.ts","this.app.use(cors())")
    for n, endpoint in [(245,"chatflows"),(246,"public-chatflows"),(247,"chatflows-streaming"),(248,"credentials")]:
        add(2023,n,"packages/server/src/index.ts",f"/api/v1/{endpoint}/:id")
    for n, pattern, text in [
        (76,"datahub-frontend/app/controllers/Application.java","proxy("),
        (77,"datahub-frontend/app/controllers/AuthenticationController.java","redirect(redirectPath)"),
        (78,"metadata-service/auth-impl/**/StatelessTokenService.java",".parse(accessToken)"),
        (79,"**/NoOpAuthenticator.java","class NoOpAuthenticator"),
        (80,"datahub-frontend/app/controllers/Application.java","String.format("),
        (81,"datahub-frontend/app/security/AuthenticationManager.java","catch (Exception e)"),
        (82,"**/SecretUtils.java","AES/ECB"),
        (83,"datahub-frontend/app/controllers/CentralLogoutController.java","executeLogout("),
        (86,"**/*.gradle","pac4j"),
        (87,"**/*.java","class Neo4jGraphService"),
    ]: add(2022,n,pattern,text)
    for n, pattern, text in [
        (60,"app/controllers/submissions_controller.rb","def update_files"),
        (62,"app/controllers/automated_tests_controller.rb","class AutomatedTestsController"),
        (63,"app/controllers/starter_file_groups_controller.rb","def update_files"),
        (64,"app/controllers/api/starter_file_groups_controller.rb","class StarterFileGroupsController"),
        (65,"app/controllers/automated_tests_controller.rb","def download_file"),
        (66,"app/controllers/exam_templates_controller.rb","def download_error_file"),
        (67,"app/controllers/exam_templates_controller.rb","def download_generate"),
        (68,"app/controllers/starter_file_groups_controller.rb","def download_file"),
        (182,"app/controllers/camaleon_cms/admin/media_controller.rb","def upload"),
        (183,"app/controllers/camaleon_cms/admin/media_controller.rb","def download_private_file"),
        (184,"app/helpers/camaleon_cms/uploader_helper.rb","def upload_file"),
        (185,"app/views/camaleon_cms/admin/settings/custom_fields/_render.html.erb","eval(field.name)"),
        (186,"app/uploaders/camaleon_cms_local_uploader.rb","def delete_file"),
    ]: add(2024,n,pattern,text)
    for n, function in [(12,"preprocess_dataset"),(13,"extract_f0_feature"),(14,"click_train"),(15,"change_info_")]:
        add(2025,n,"infer-web.py",f"def {function}(")
    for n, function in [(16,"show_info"),(17,"extract_small_model"),(18,"change_info"),(19,"merge")]:
        add(2025,n,"infer/lib/train/process_ckpt.py",f"def {function}(")
    add(2025,20,"infer/modules/onnx/export.py","torch.load(ModelPath")
    for n, cls in [(21,"AudioPre"),(22,"AudioPreDeEcho")]:
        add(2025,n,"infer/modules/uvr5/preprocess.py",f"class {cls}:")
    for n, function in [(45,"open_slice"),(46,"open_denoise"),(47,"open_asr"),(48,"change_label")]:
        add(2025,n,"webui.py",f"def {function}(")
    for n, pattern, text in [
        (49,"tools/uvr5/vr.py","class AudioPre:"),
        (50,"tools/uvr5/vr.py","class AudioPreDeEcho:"),
        (51,"tools/uvr5/bsroformer.py","class Roformer_Loader"),
        (52,"GPT_SoVITS/inference_webui.py","def change_gpt_weights("),
        (53,"GPT_SoVITS/process_ckpt.py","def load_sovits_new("),
    ]: add(2025,n,pattern,text)
    return checks


def check_sources(data, work):
    checks = anchors()
    report = {"catalog_sha256": digest(data), "scope": "symbol presence only; not exploit validation",
              "cases": []}
    for case in data["cases"]:
        lock = checked_lock(data,case,work)
        root = Path(lock["source_dir"])
        row = {"case_id":case["id"], "repository":case["repository"],
               "commit":lock["commit"], "tree_sha256":lock["tree_sha256"], "labels":[]}
        for label in case["labels"]:
            pattern, text = checks[label["id"]]
            matches=[]
            for path in sorted(root.glob(pattern)):
                if path.is_file():
                    content=path.read_bytes()
                    for line_no,line in enumerate(content.decode("utf-8",errors="replace").splitlines(),1):
                        if text in line:
                            matches.append({"path":path.relative_to(root).as_posix(),"line":line_no,
                                            "file_sha256":hashlib.sha256(content).hexdigest()})
            row["labels"].append({"label_id":label["id"], "status":"anchor_found" if matches else "needs_investigation",
                                   "matches":matches, "pattern":pattern, "anchor":text})
        report["cases"].append(row)
    return report
