from __future__ import annotations

import base64
import json
import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class AppxExtractionError(Exception):
    """Expected extractor failure."""


@dataclass
class Course:
    id: str
    name: str


class AppxExtractor:
    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        self.logger = logging.getLogger(self.__class__.__name__)
        self.decrypt_key = os.getenv("APPX_DECRYPT_KEY", "638udh3829162018").encode("utf-8")
        self.decrypt_iv = os.getenv("APPX_DECRYPT_IV", "fedcba9876543210").encode("utf-8")

    def extract(
        self,
        api_base: str,
        email: str | None,
        password: str | None,
        token: str | None,
        user_id: str | None,
        selected_course_ids: list[str] | None,
    ) -> dict[str, Any]:
        normalized_base = self._normalize_api_base(api_base)
        session = self._session()

        auth = self._authenticate(
            session=session,
            api_base=normalized_base,
            email=email,
            password=password,
            token=token,
            user_id=user_id,
        )
        headers = auth["headers"]

        courses = self._get_all_courses(session, normalized_base, headers, auth["user_id"])
        if not courses:
            raise AppxExtractionError("No batches found for this account/token.")

        if selected_course_ids:
            selected = {str(course_id) for course_id in selected_course_ids}
            courses = [course for course in courses if course.id in selected]
            if not courses:
                raise AppxExtractionError("None of the requested `course_ids` were found.")

        all_lines: list[str] = []
        for course in courses:
            self.logger.info("Extracting course '%s' (%s)", course.name, course.id)
            all_lines.extend(self._extract_course(session, normalized_base, headers, course))

        unique_lines = self._dedupe_lines(all_lines)
        if not unique_lines:
            raise AppxExtractionError("Extraction finished but no media/resource URLs were found.")

        output_file = self.output_dir / f"{self._slugify(courses[0].name)}_{len(courses)}_courses.txt"
        output_file.write_text("\n".join(unique_lines) + "\n", encoding="utf-8")

        return {
            "api_base": normalized_base,
            "user_id": auth["user_id"],
            "course_count": len(courses),
            "url_count": len(unique_lines),
            "file": output_file.name,
            "download_url": f"/files/{output_file.name}",
            "courses": [{"id": c.id, "name": c.name} for c in courses],
        }

    def _normalize_api_base(self, api_base: str) -> str:
        if not api_base.startswith(("http://", "https://")):
            api_base = f"https://{api_base}"
        return api_base.rstrip("/")

    def _session(self) -> requests.Session:
        session = requests.Session()
        retry = Retry(
            total=4,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=frozenset(["GET", "POST"]),
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update(
            {
                "Accept": "application/json, text/plain, */*",
                "User-Agent": os.getenv(
                    "EXTRACTOR_USER_AGENT",
                    "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36",
                ),
            }
        )
        return session

    def _authenticate(
        self,
        session: requests.Session,
        api_base: str,
        email: str | None,
        password: str | None,
        token: str | None,
        user_id: str | None,
    ) -> dict[str, Any]:
        base_headers = {
            "Client-Service": "Appx",
            "source": "website",
            "Auth-Key": "appxapi",
        }

        if token:
            detected_user_id = user_id or self._resolve_user_id(session, api_base, token)
            if not detected_user_id:
                raise AppxExtractionError(
                    "Token login requires `user_id` in latest APIs when profile endpoints are restricted."
                )
            return {
                "token": token,
                "user_id": str(detected_user_id),
                "headers": {**base_headers, "Authorization": token, "User-ID": str(detected_user_id)},
            }

        assert email and password
        login_payload = {"email": email, "password": password}
        login_headers = {
            "Auth-Key": "appxapi",
            "User-Id": "-2",
            "Authorization": "",
            "User_app_category": "",
            "Language": "en",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": session.headers["User-Agent"],
        }

        login_endpoints = [
            "/post/userLogin",
            "/api/v1/post/userLogin",
            "/v2/post/userLogin",
        ]

        for endpoint in login_endpoints:
            response = session.post(
                f"{api_base}{endpoint}",
                data=login_payload,
                headers=login_headers,
                timeout=25,
            )
            body = self._safe_json(response)
            data = body.get("data") or {}
            if response.ok and data.get("token"):
                return {
                    "token": data["token"],
                    "user_id": str(data.get("userid") or data.get("user_id") or ""),
                    "headers": {
                        **base_headers,
                        "Authorization": data["token"],
                        "User-ID": str(data.get("userid") or data.get("user_id") or ""),
                    },
                }

        raise AppxExtractionError("Login failed. Verify credentials/API base and try again.")

    def _resolve_user_id(self, session: requests.Session, api_base: str, token: str) -> str | None:
        headers = {
            "Client-Service": "Appx",
            "source": "website",
            "Auth-Key": "appxapi",
            "Authorization": token,
            "User-ID": "",
        }
        candidates = [
            "/get/userprofile",
            "/get/profile",
            "/get/get_user_profile",
        ]
        for endpoint in candidates:
            response = session.get(f"{api_base}{endpoint}", headers=headers, timeout=20)
            body = self._safe_json(response)
            data = body.get("data") or {}
            user_id = data.get("id") or data.get("userid") or data.get("user_id")
            if user_id:
                return str(user_id)
        return None

    def _get_all_courses(
        self,
        session: requests.Session,
        api_base: str,
        headers: dict[str, str],
        user_id: str,
    ) -> list[Course]:
        course_map: dict[str, str] = {}

        purchase_endpoints = [
            f"/get/get_all_purchases?userid={user_id}&item_type=10",
            f"/api/v1/get/get_all_purchases?userid={user_id}&item_type=10",
        ]

        for endpoint in purchase_endpoints:
            response = session.get(f"{api_base}{endpoint}", headers=headers, timeout=25)
            body = self._safe_json(response)
            for item in body.get("data", []):
                for course in item.get("coursedt", []):
                    if course.get("id"):
                        course_map[str(course["id"])] = course.get("course_name", f"course_{course['id']}")
            if course_map:
                break

        non_purchased_endpoints = [
            f"/get/mycourseweb?userid={user_id}",
            "/get/mycourseweb",
            f"/api/v1/get/mycourseweb?userid={user_id}",
        ]

        for endpoint in non_purchased_endpoints:
            response = session.get(f"{api_base}{endpoint}", headers=headers, timeout=25)
            body = self._safe_json(response)
            for course in body.get("data", []):
                if course.get("id"):
                    course_map[str(course["id"])] = course.get("course_name", f"course_{course['id']}")

        return [Course(id=course_id, name=name) for course_id, name in course_map.items()]

    def _extract_course(
        self,
        session: requests.Session,
        api_base: str,
        headers: dict[str, str],
        course: Course,
    ) -> list[str]:
        lines: list[str] = []

        lines.extend(self._extract_course_v2(session, api_base, headers, course))
        lines.extend(self._extract_course_v3(session, api_base, headers, course))

        return lines

    def _extract_course_v2(
        self,
        session: requests.Session,
        api_base: str,
        headers: dict[str, str],
        course: Course,
    ) -> list[str]:
        lines: list[str] = []
        pending = ["-1"]
        seen_folders: set[str] = set()

        while pending:
            folder_id = pending.pop()
            if folder_id in seen_folders:
                continue
            seen_folders.add(folder_id)

            response = session.get(
                f"{api_base}/get/folder_contentsv2?course_id={course.id}&parent_id={folder_id}",
                headers=headers,
                timeout=25,
            )
            body = self._safe_json(response)
            data = body.get("data", [])

            for item in data:
                item_id = item.get("id")
                material_type = (item.get("material_type") or "").upper()
                if material_type == "FOLDER" and item_id:
                    pending.append(str(item_id))
                    continue

                if item_id:
                    details = self._fetch_video_details(session, api_base, headers, course.id, str(item_id), folder_wise=1)
                    lines.extend(self._extract_links_from_video(details))

        return lines

    def _extract_course_v3(
        self,
        session: requests.Session,
        api_base: str,
        headers: dict[str, str],
        course: Course,
    ) -> list[str]:
        lines: list[str] = []

        subjects_res = session.get(
            f"{api_base}/get/allsubjectfrmlivecourseclass?courseid={course.id}&start=-1",
            headers=headers,
            timeout=25,
        )
        subjects = self._safe_json(subjects_res).get("data", [])

        for subject in subjects:
            subject_id = subject.get("id")
            if not subject_id:
                continue
            topics_res = session.get(
                f"{api_base}/get/alltopicfrmlivecourseclass?courseid={course.id}&subjectid={subject_id}&start=-1",
                headers=headers,
                timeout=25,
            )
            topics = self._safe_json(topics_res).get("data", [])

            for topic in topics:
                topic_id = topic.get("id")
                if not topic_id:
                    continue
                classes_res = session.get(
                    f"{api_base}/get/livecourseclassbycoursesubtopconceptapiv3"
                    f"?courseid={course.id}&subjectid={subject_id}&topicid={topic_id}&conceptid=&start=-1",
                    headers=headers,
                    timeout=25,
                )
                classes = self._safe_json(classes_res).get("data", [])
                for cls in classes:
                    video_id = cls.get("id")
                    if not video_id:
                        continue
                    details = self._fetch_video_details(session, api_base, headers, course.id, str(video_id), folder_wise=0)
                    lines.extend(self._extract_links_from_video(details))

        return lines

    def _fetch_video_details(
        self,
        session: requests.Session,
        api_base: str,
        headers: dict[str, str],
        course_id: str,
        video_id: str,
        folder_wise: int,
    ) -> dict[str, Any]:
        response = session.get(
            f"{api_base}/get/fetchVideoDetailsById?course_id={course_id}&folder_wise_course={folder_wise}&ytflag=0&video_id={video_id}",
            headers=headers,
            timeout=25,
        )
        return self._safe_json(response).get("data", {})

    def _extract_links_from_video(self, details: dict[str, Any]) -> list[str]:
        title = details.get("Title") or details.get("title") or "untitled"
        found: list[str] = []

        if details.get("download_link"):
            link = self._decrypt_or_plain(details["download_link"])
            found.append(f"{title}:{link}")

        for enc in details.get("encrypted_links", []) or []:
            path = enc.get("path")
            if not path:
                continue
            path_value = self._decrypt_or_plain(path)
            if enc.get("key"):
                dec_key = self._decrypt_or_plain(enc["key"])
                try:
                    dec_key = base64.b64decode(dec_key).decode("utf-8")
                except Exception:  # noqa: BLE001
                    pass
                found.append(f"{title}:{path_value}*{dec_key}")
            else:
                found.append(f"{title}:{path_value}")

        for field in ("pdf_link", "pdf_link2", "material_url", "resource_url"):
            value = details.get(field)
            if value:
                found.append(f"{title}:{self._decrypt_or_plain(value)}")

        return found

    def _decrypt_or_plain(self, value: str) -> str:
        if not value:
            return value

        candidate = value.split(":", 1)[0]
        if re.fullmatch(r"[A-Za-z0-9+/=]+", candidate or ""):
            try:
                encrypted = base64.b64decode(candidate)
                if encrypted:
                    cipher = AES.new(self.decrypt_key, AES.MODE_CBC, self.decrypt_iv)
                    plain = unpad(cipher.decrypt(encrypted), AES.block_size)
                    return plain.decode("utf-8")
            except Exception:  # noqa: BLE001
                return value
        return value

    def _safe_json(self, response: requests.Response) -> dict[str, Any]:
        try:
            return response.json()
        except json.JSONDecodeError:
            return {}

    def _dedupe_lines(self, lines: list[str]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for line in lines:
            cleaned = line.strip()
            if not cleaned or cleaned in seen:
                continue
            seen.add(cleaned)
            out.append(cleaned)
        return out

    def _slugify(self, value: str) -> str:
        return re.sub(r"[^a-zA-Z0-9_-]", "_", value).strip("_") or "batch"
