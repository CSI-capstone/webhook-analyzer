"""CLI 종료 코드와 입력 경로 회귀 시험."""
import contextlib
import io
import tempfile
import unittest
from pathlib import Path
import main


class CLITests(unittest.TestCase):
    def run_cli(self,source,*options):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'handler.py';path.write_text(source)
            args=main.build_parser().parse_args(['--code',str(path),*options])
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                return main.run(args)

    def test_no_handler_is_input_incomplete(self):
        self.assertEqual(self.run_cli('x=1','--sast-only'),2)

    def test_missing_signature_is_detected(self):
        self.assertEqual(self.run_cli("@app.post('/webhook')\nasync def hook(request):\n    return {}\n",'--sast-only'),1)

    def test_invalid_tolerance_rejected(self):
        self.assertEqual(self.run_cli('x=1','--sast-only','--timestamp-tolerance','0'),2)

    def test_non_http_url_rejected(self):
        self.assertEqual(self.run_cli('x=1','--url','file:///tmp'),2)


if __name__=='__main__': unittest.main()
