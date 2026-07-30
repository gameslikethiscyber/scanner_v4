import uuid
import json
import logging
import threading
from typing import Optional, Dict, List, Any
from datetime import datetime, timezone

logger = logging.getLogger('SeaScanner.OAST')

try:
    from interactsh import Interactsh

    INTERACTSH_AVAILABLE = True
except ImportError:
    Interactsh = None
    INTERACTSH_AVAILABLE = False


class OastManager:
    def __init__(self, server: str = "oast.fun", poll_interval: int = 5, poll_attempts: int = 3):
        self.server = server
        self.poll_interval = poll_interval
        self.poll_attempts = poll_attempts
        self._client: Optional[Any] = None
        self._interactions: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._payloads: Dict[str, Dict[str, Any]] = {}

    def start(self) -> bool:
        if not INTERACTSH_AVAILABLE or Interactsh is None:
            logger.warning("Interactsh not available, OAST disabled")
            return False
        try:
            self._client = Interactsh(server=self.server)
            self._client.register()
            logger.info("OAST client registered with server %s", self.server)
            return True
        except Exception as e:
            logger.error("Failed to register OAST client: %s", e)
            return False

    def generate_payload(self, scan_id: int, scanner_name: str, param: str) -> Optional[str]:
        if not self._client:
            return None
        try:
            unique_id = uuid.uuid4().hex[:12]
            subdomain = f"{scanner_name.lower().replace(' ', '-')}-{unique_id}"
            payload_url = f"http://{subdomain}.{self.server}/"
            with self._lock:
                self._payloads[subdomain] = {
                    "scan_id": scan_id,
                    "scanner": scanner_name,
                    "param": param,
                    "payload": payload_url,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }
            return payload_url
        except Exception as e:
            logger.error("Failed to generate OAST payload: %s", e)
            return None

    def poll(self) -> List[Dict[str, Any]]:
        if not self._client:
            return []
        interactions = []
        try:
            raw = self._client.poll()
            if raw:
                for entry in raw if isinstance(raw, list) else [raw]:
                    interaction = self._parse_interaction(entry)
                    if interaction:
                        interactions.append(interaction)
        except Exception as e:
            logger.debug("OAST poll error: %s", e)
        with self._lock:
            self._interactions.extend(interactions)
        return interactions

    def poll_all(self) -> List[Dict[str, Any]]:
        all_interactions = []
        for _ in range(self.poll_attempts):
            import time
            time.sleep(self.poll_interval)
            result = self.poll()
            all_interactions.extend(result)
        return all_interactions

    def check_interaction(self, payload_url: str) -> bool:
        if not payload_url:
            return False
        for interaction in self._interactions:
            if payload_url in str(interaction.get("data", "")):
                return True
            if payload_url in str(interaction.get("protocol", "")):
                return True
        return False

    def get_matching_interactions(self, scan_id: int) -> List[Dict[str, Any]]:
        matching = []
        with self._lock:
            for subdomain, info in self._payloads.items():
                if info["scan_id"] == scan_id:
                    for interaction in self._interactions:
                        if subdomain in str(interaction.get("data", "")):
                            matching.append({
                                "payload_info": info,
                                "interaction": interaction,
                            })
        return matching

    def _parse_interaction(self, raw: Any) -> Optional[Dict[str, Any]]:
        try:
            if isinstance(raw, dict):
                return {
                    "protocol": raw.get("protocol", ""),
                    "data": raw.get("data", ""),
                    "remote_addr": raw.get("remote-address", ""),
                    "timestamp": raw.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    "raw": raw,
                }
            if hasattr(raw, "__dict__"):
                return {
                    "protocol": getattr(raw, "protocol", ""),
                    "data": getattr(raw, "data", ""),
                    "remote_addr": getattr(raw, "remote_address", ""),
                    "timestamp": getattr(raw, "timestamp", datetime.now(timezone.utc).isoformat()),
                    "raw": raw.__dict__,
                }
            return {"data": str(raw), "timestamp": datetime.now(timezone.utc).isoformat()}
        except Exception as e:
            logger.debug("Failed to parse OAST interaction: %s", e)
            return None

    def close(self):
        if self._client:
            try:
                self._client.deregister()
            except Exception:
                pass
            self._client = None
