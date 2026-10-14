"""P7.4 — Spanish report support."""
from __future__ import annotations
from typing import Any

ES = {
    "board_title": "RESUMEN PARA LA JUNTA — UNA PÁGINA",
    "client": "Cliente", "engagement": "Compromiso", "date": "Fecha", "scope": "Alcance", "sector": "Sector",
    "health": "SALUD DE SEGURIDAD (como un chequeo médico)",
    "posture_score": "Puntuación de postura", "band": "Nivel",
    "bands_help": "80–100 Base sólida   60–79 Brechas manejables\n  40–59 Requiere trabajo enfocado   Bajo 40 Atención urgente",
    "top_risks": "PRINCIPALES RIESGOS PARA LA DIRECCIÓN",
    "no_high": "No se señalaron problemas de alta prioridad en esta ventana de análisis.",
    "money_at_stake": "DINERO EN JUEGO (orden de magnitud)",
    "progress": "PROGRESO DESDE EL ÚLTIMO ANÁLISIS (si es retest)",
    "fixed": "Corregido / cerrado", "still_open": "Aún abierto", "newly": "Recién introducido",
    "next_steps": "QUÉ HACER A CONTINUACIÓN",
    "next_1": "1. Asigne un responsable para cada riesgo principal esta semana.",
    "next_2": "2. Pida a TI o a su proveedor un plan de corrección de una página.",
    "next_3": "3. Programe un retest después de las correcciones — medimos el delta.",
    "next_4": "4. Conserve esta hoja con los papeles de la junta.",
    "honest_scope": "ALCANCE HONESTO",
    "honest_body": "Este es un análisis de red en un momento determinado bajo reglas de compromiso acordadas.\n  No es monitoreo 24/7.",
    "sources": "FUENTES DE LOS RANGOS DE COSTO", "contact": "Contacto",
}

def translate_board_skeleton(*, lang: str, company_name: str, tagline: str, client_name: str,
    session_id: str, date_str: str, target: str, sector: str, score: str, band: str,
    top_lines: list[str], money_line: str, fixed: Any, still: Any, new: Any,
    source_note: str, email: str, phone: str, website: str) -> str:
    if not (lang or "").lower().startswith("es"):
        return ""
    lines = ["═" * 72, f"  {company_name}".center(72), f"  {ES['board_title']}".center(72),
             f"  {tagline}".center(72), "═" * 72, "",
             f"{ES['client']}:        {client_name or 'Compromiso autorizado'}",
             f"{ES['engagement']}:    {session_id}", f"{ES['date']}:          {date_str}",
             f"{ES['scope']}:         {target}", f"{ES['sector']}:        {sector}", "",
             "─" * 72, ES["health"], "─" * 72,
             f"  {ES['posture_score']}:   {score} / 100", f"  {ES['band']}:            {band or 'n/a'}", "",
             f"  {ES['bands_help']}", "", "─" * 72, ES["top_risks"], "─" * 72]
    if not top_lines:
        lines.append(f"  {ES['no_high']}")
    else:
        lines.extend(top_lines)
    lines += ["", "─" * 72, ES["money_at_stake"], "─" * 72, f"  {money_line}", "",
              "─" * 72, ES["progress"], "─" * 72,
              f"  {ES['fixed']}:   {fixed}", f"  {ES['still_open']}:       {still}", f"  {ES['newly']}: {new}", "",
              "─" * 72, ES["next_steps"], "─" * 72,
              f"  {ES['next_1']}", f"  {ES['next_2']}", f"  {ES['next_3']}", f"  {ES['next_4']}", "",
              "─" * 72, ES["honest_scope"], "─" * 72, f"  {ES['honest_body']}", "",
              "─" * 72, ES["sources"], "─" * 72, f"  {source_note}", "",
              f"  {ES['contact']}: {email} · {phone}", f"  Web:     {website}", "═" * 72]
    return "\n".join(lines)
