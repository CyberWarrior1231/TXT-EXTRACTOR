from __future__ import annotations

import logging
import os
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

from service.extractor import AppxExtractionError, AppxExtractor


def _build_app() -> Flask:
    app = Flask(__name__)

    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )
    logger = logging.getLogger("txt-extractor")

    output_dir = Path(os.getenv("OUTPUT_DIR", "outputs")).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    extractor = AppxExtractor(output_dir=output_dir)

    @app.get("/health")
    def health() -> tuple:
        return jsonify({"status": "ok"}), 200

    @app.post("/extract")
    def extract() -> tuple:
        payload = request.get_json(silent=True) or {}

        api_base = payload.get("api_base")
        email = payload.get("email")
        password = payload.get("password")
        token = payload.get("token")
        user_id = payload.get("user_id")
        course_ids = payload.get("course_ids")

        if not api_base:
            return jsonify({"error": "`api_base` is required"}), 400

        if not token and not (email and password):
            return jsonify({"error": "Provide either `token` OR `email` + `password`"}), 400

        if course_ids is not None and not isinstance(course_ids, list):
            return jsonify({"error": "`course_ids` must be a list when provided"}), 400

        try:
            result = extractor.extract(
                api_base=api_base,
                email=email,
                password=password,
                token=token,
                user_id=user_id,
                selected_course_ids=course_ids,
            )
            return jsonify(result), 200
        except AppxExtractionError as exc:
            logger.warning("Extraction failed: %s", exc)
            return jsonify({"error": str(exc)}), 400
        except Exception as exc:  # noqa: BLE001
            logger.exception("Unexpected extraction error")
            return jsonify({"error": "Internal server error", "details": str(exc)}), 500

    @app.get("/files/<path:filename>")
    def files(filename: str):
        return send_from_directory(output_dir, filename, as_attachment=True)

    return app


app = _build_app()


if __name__ == "__main__":
   app.run(host="0.0.0.0", port=int(os.getenv("PORT", "10000")))
