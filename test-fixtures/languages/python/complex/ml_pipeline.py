import os
import sys
import json
import subprocess
import shlex
import pickle
import hashlib
import tempfile
import re


class ModelConfig:
    """Configuration for ML model loading"""

    def __init__(self, path, name, version="latest"):
        self.path = path
        self.name = name
        self.version = version
        self.metadata = {}

    def resolve_path(self):
        """Resolves model path - may include user input"""
        if self.version != "latest":
            return os.path.join(self.path, self.version)
        return self.path

    def validate(self):
        if not self.name or len(self.name) > 100:
            raise ValueError("Invalid model name")
        return True


class ExternalModelRunner:
    """Runs external model binaries"""

    def __init__(self, model_config):
        self.config = model_config

    def prepare(self):
        """Prepares the model for execution"""
        resolved = self.config.resolve_path()
        return resolved

    def execute(self, resolved_path):
        """VULN: Command injection - Deep Chain 2 sink"""
        cmd = "python model_runner.py --model " + resolved_path
        os.system(cmd)
        return {"status": "executed"}

    def execute_safe(self, resolved_path):
        """Safe version: uses subprocess with list args"""
        safe_path = shlex.quote(resolved_path)
        subprocess.run(["python", "model_runner.py", "--model", safe_path], check=True)
        return {"status": "executed"}


class ModelLoader:
    """Loads ML models from various sources"""

    def __init__(self, model_path, model_name):
        self.model_path = model_path
        self.model_name = model_name
        self.config = ModelConfig(model_path, model_name)

    def load(self):
        """Deep Chain 2: path flows through config -> runner -> os.system"""
        self.config.validate()
        runner = ExternalModelRunner(self.config)
        resolved = runner.prepare()
        result = runner.execute(resolved)
        return result

    def load_safe(self):
        """Safe version"""
        self.config.validate()
        runner = ExternalModelRunner(self.config)
        resolved = runner.prepare()
        result = runner.execute_safe(resolved)
        return result

    def load_from_pickle(self, data):
        """VULN: Insecure deserialization"""
        model = pickle.loads(data)
        return model

    def load_from_file(self, filepath):
        """VULN: Path traversal in model loading"""
        with open(filepath, "rb") as f:
            return pickle.load(f)

    def download_model(self, url):
        """VULN: SSRF via model download"""
        import requests
        response = requests.get(url)
        model_data = response.content
        save_path = os.path.join("/tmp/models", self.model_name)
        with open(save_path, "wb") as f:
            f.write(model_data)
        return save_path


class ModelValidator:
    """Validates model files before loading"""

    ALLOWED_FORMATS = {".h5", ".pt", ".onnx", ".pb", ".safetensors"}

    def __init__(self):
        self.errors = []

    def validate_format(self, filepath):
        ext = os.path.splitext(filepath)[1]
        if ext not in self.ALLOWED_FORMATS:
            self.errors.append(f"Unsupported format: {ext}")
            return False
        return True

    def validate_checksum(self, filepath, expected_hash):
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        actual = sha256.hexdigest()
        if actual != expected_hash:
            self.errors.append("Checksum mismatch")
            return False
        return True

    def validate_size(self, filepath, max_size_mb=500):
        size = os.path.getsize(filepath)
        if size > max_size_mb * 1024 * 1024:
            self.errors.append("Model too large")
            return False
        return True


class InferenceEngine:
    """Runs model inference"""

    def __init__(self, model_name):
        self.model_name = model_name
        self.model = None

    def load_model(self):
        model_dir = os.environ.get("MODEL_DIR", "/var/models")
        model_path = os.path.join(model_dir, self.model_name)
        with open(model_path, "rb") as f:
            self.model = pickle.load(f)

    def predict(self, input_data):
        if self.model is None:
            self.load_model()
        return self.model.predict(input_data)

    def batch_predict(self, inputs):
        results = []
        for item in inputs:
            results.append(self.predict(item))
        return results


class DataPreprocessor:
    """Preprocesses data for ML models"""

    def __init__(self):
        self.transformers = []

    def add_transformer(self, transformer):
        self.transformers.append(transformer)

    def transform(self, data):
        result = data
        for t in self.transformers:
            result = t.apply(result)
        return result

    def normalize(self, values):
        min_val = min(values)
        max_val = max(values)
        if max_val == min_val:
            return [0.0] * len(values)
        return [(v - min_val) / (max_val - min_val) for v in values]


class PipelineManager:
    """Manages ML pipelines"""

    def __init__(self):
        self.pipelines = {}

    def register(self, name, pipeline):
        self.pipelines[name] = pipeline

    def run(self, name, data):
        pipeline = self.pipelines.get(name)
        if pipeline is None:
            raise ValueError(f"Pipeline not found: {name}")
        return pipeline.execute(data)

    def run_shell_pipeline(self, script_path):
        """VULN: Command injection via script path"""
        cmd = f"bash {script_path}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.stdout

    def run_shell_pipeline_safe(self, script_path):
        """Safe version"""
        allowed_scripts = ["/opt/pipelines/train.sh", "/opt/pipelines/evaluate.sh"]
        if script_path not in allowed_scripts:
            raise ValueError("Script not allowed")
        result = subprocess.run(["bash", script_path], capture_output=True, text=True)
        return result.stdout
