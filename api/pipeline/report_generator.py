# ============================================================
# report_generator.py — Génération rapport PDF
# ============================================================
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import (getSampleStyleSheet,
                                   ParagraphStyle)
from reportlab.lib.colors import (HexColor, black,
                                   white, red, green)
from reportlab.lib.units import cm
from reportlab.platypus import (SimpleDocTemplate,
    Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak)
from reportlab.lib.enums import TA_CENTER, TA_LEFT
import io
from datetime import datetime

# ── Couleurs ───────────────────────────────────────────────
DARK_BLUE    = HexColor('#1a2744')
ACCENT_BLUE  = HexColor('#2980b9')
LIGHT_BLUE   = HexColor('#d6eaf8')
GREEN_COLOR  = HexColor('#27ae60')
LIGHT_GREEN  = HexColor('#d5f5e3')
RED_COLOR    = HexColor('#e74c3c')
LIGHT_RED    = HexColor('#fadbd8')
ORANGE       = HexColor('#e67e22')
LIGHT_ORANGE = HexColor('#fdebd0')
GRAY         = HexColor('#7f8c8d')
LIGHT_GRAY   = HexColor('#f2f3f4')

PAGE_W, PAGE_H = A4

# ── Styles ─────────────────────────────────────────────────
styles = getSampleStyleSheet()

title_style = ParagraphStyle(
    'Title', fontSize=20, textColor=white,
    fontName='Helvetica-Bold',
    alignment=TA_CENTER, spaceAfter=4, leading=24)

h1_style = ParagraphStyle(
    'H1', fontSize=14, textColor=white,
    fontName='Helvetica-Bold',
    spaceBefore=4, spaceAfter=4, leading=18)

h2_style = ParagraphStyle(
    'H2', fontSize=12, textColor=DARK_BLUE,
    fontName='Helvetica-Bold',
    spaceBefore=8, spaceAfter=4, leading=15)

h3_style = ParagraphStyle(
    'H3', fontSize=10, textColor=ACCENT_BLUE,
    fontName='Helvetica-Bold',
    spaceBefore=6, spaceAfter=3, leading=13)

body_style = ParagraphStyle(
    'Body', fontSize=10, textColor=black,
    fontName='Helvetica',
    spaceBefore=2, spaceAfter=2, leading=14)

small_style = ParagraphStyle(
    'Small', fontSize=8, textColor=GRAY,
    fontName='Helvetica-Oblique',
    spaceBefore=2, spaceAfter=2, leading=11)


def section_header(text, color=DARK_BLUE):
    data = [[Paragraph(text, h1_style)]]
    t = Table(data, colWidths=[17*cm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), color),
        ('PADDING', (0,0), (-1,-1), 8),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
    ]))
    return t


def info_box(text, bg=LIGHT_BLUE, border=ACCENT_BLUE):
    data = [[Paragraph(text, body_style)]]
    t = Table(data, colWidths=[17*cm])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), bg),
        ('BOX', (0,0), (-1,-1), 1.5, border),
        ('PADDING', (0,0), (-1,-1), 8),
    ]))
    return t


def make_table(headers, rows, col_widths=None):
    if col_widths is None:
        col_widths = [17*cm / len(headers)] * len(headers)
    data = [headers] + rows
    t = Table(data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), DARK_BLUE),
        ('TEXTCOLOR', (0,0), (-1,0), white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 9),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('GRID', (0,0), (-1,-1), 0.5, GRAY),
        ('ROWBACKGROUNDS', (0,1), (-1,-1),
         [LIGHT_GRAY, white]),
        ('PADDING', (0,0), (-1,-1), 6),
    ]))
    return t


def header_footer(canvas, doc):
    """En-tête et pied de page sur chaque page."""
    canvas.saveState()
    # Header
    canvas.setFillColor(DARK_BLUE)
    canvas.rect(1.5*cm, PAGE_H-1.8*cm,
                PAGE_W-3*cm, 0.7*cm, fill=1, stroke=0)
    canvas.setFillColor(white)
    canvas.setFont('Helvetica-Bold', 9)
    canvas.drawString(1.8*cm, PAGE_H-1.45*cm,
        'Rapport d\'Analyse de Sécurité — Système ML+DL')
    canvas.drawRightString(PAGE_W-1.8*cm,
        PAGE_H-1.45*cm,
        datetime.now().strftime('%d/%m/%Y %H:%M'))
    # Footer
    canvas.setFillColor(DARK_BLUE)
    canvas.rect(1.5*cm, 0.8*cm,
                PAGE_W-3*cm, 0.6*cm, fill=1, stroke=0)
    canvas.setFillColor(white)
    canvas.setFont('Helvetica', 8)
    canvas.drawString(1.8*cm, 1.0*cm,
        'Confidentiel — Généré automatiquement')
    canvas.drawRightString(PAGE_W-1.8*cm, 1.0*cm,
        f'Page {doc.page}')
    canvas.restoreState()


def generate_report(
        filename: str,
        sha256: str,
        file_size: int,
        prediction: dict,
        static_info: dict = None,
        dynamic_report: dict = None) -> bytes:
    """
    Génère un rapport PDF complet en mémoire.

    Args:
        filename    : nom du fichier analysé
        sha256      : hash SHA256 du fichier
        file_size   : taille en bytes
        prediction  : résultat du Weighted Vote
        static_info : infos statiques (optionnel)
        dynamic_report : rapport VirusTotal (optionnel)

    Returns:
        bytes du PDF généré
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        leftMargin=1.5*cm, rightMargin=1.5*cm,
        topMargin=2.5*cm, bottomMargin=2*cm,
        title=f'Rapport Analyse — {filename}')

    story = []
    verdict    = prediction.get("verdict", "INCONNU")
    confidence = prediction.get("confidence", 0)
    is_malware = prediction.get("is_malware", False)
    votes      = prediction.get("votes", [])

    # Couleurs selon verdict
    verdict_color = RED_COLOR if is_malware \
                    else GREEN_COLOR
    verdict_bg    = LIGHT_RED if is_malware \
                    else LIGHT_GREEN
    verdict_icon  = "❌ MALWARE DÉTECTÉ" if is_malware \
                    else "✅ FICHIER BÉNIN"

    # ══════════════════════════════════════════════════
    # PAGE DE GARDE
    # ══════════════════════════════════════════════════
    story.append(Spacer(1, 1*cm))

    # Titre principal
    cover_data = [[Paragraph(
        '🛡️  Rapport d\'Analyse de Sécurité',
        title_style)]]
    cover_table = Table(cover_data, colWidths=[17*cm])
    cover_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), DARK_BLUE),
        ('PADDING', (0,0), (-1,-1), 20),
        ('TOPPADDING', (0,0), (-1,-1), 20),
        ('BOTTOMPADDING', (0,0), (-1,-1), 20),
    ]))
    story.append(cover_table)
    story.append(Spacer(1, 0.5*cm))

    # Verdict en grand
    verdict_data = [[Paragraph(
        f'<b>{verdict_icon}</b>',
        ParagraphStyle('V', fontSize=18,
            textColor=verdict_color,
            fontName='Helvetica-Bold',
            alignment=TA_CENTER))]]
    vt = Table(verdict_data, colWidths=[17*cm])
    vt.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), verdict_bg),
        ('BOX', (0,0), (-1,-1), 2, verdict_color),
        ('PADDING', (0,0), (-1,-1), 15),
    ]))
    story.append(vt)
    story.append(Spacer(1, 0.4*cm))

    # Confiance
    conf_text = (f'Niveau de confiance : '
                 f'<b>{confidence:.1f}%</b>')
    story.append(info_box(conf_text,
        LIGHT_BLUE, ACCENT_BLUE))
    story.append(Spacer(1, 0.4*cm))

    # Informations fichier
    story.append(Paragraph(
        'Informations du fichier analysé', h2_style))
    info_rows = [
        ['Nom du fichier', filename],
        ['Taille', f'{file_size / 1024:.1f} KB'],
        ['Hash SHA256', sha256[:32] + '...'],
        ['Date d\'analyse',
         datetime.now().strftime(
             '%d/%m/%Y à %H:%M:%S')],
        ['Système d\'analyse',
         'Approche Hybride ML+DL (5 modèles)'],
    ]
    story.append(make_table(
        ['Propriété', 'Valeur'],
        info_rows, [5*cm, 12*cm]))

    story.append(PageBreak())

    # ══════════════════════════════════════════════════
    # SECTION 1 — RÉSUMÉ POUR L'UTILISATEUR
    # ══════════════════════════════════════════════════
    story.append(section_header(
        '1. Résumé — Ce que ça veut dire pour vous',
        ACCENT_BLUE))
    story.append(Spacer(1, 0.3*cm))

    if is_malware:
        story.append(info_box(
            '<b>⚠️  Ce fichier est DANGEREUX</b><br/>'
            'Notre système a détecté des '
            'caractéristiques malveillantes dans ce '
            'fichier. Il est fortement recommandé de '
            'ne PAS l\'exécuter et de le supprimer '
            'immédiatement de votre système.',
            LIGHT_RED, RED_COLOR))
        story.append(Spacer(1, 0.3*cm))
        story.append(Paragraph(
            'Que faire maintenant ?', h2_style))
        recommandations = [
            ['1', 'Ne pas exécuter ce fichier'],
            ['2', 'Supprimer le fichier immédiatement'],
            ['3',
             'Scanner votre système avec un antivirus'],
            ['4',
             'Signaler le fichier à votre équipe IT'],
            ['5',
             'Vérifier si le fichier a déjà été '
             'exécuté sur votre machine'],
        ]
        story.append(make_table(
            ['Priorité', 'Action recommandée'],
            recommandations, [2*cm, 15*cm]))
    else:
        story.append(info_box(
            '<b>✅  Ce fichier semble sûr</b><br/>'
            'Notre système n\'a détecté aucune '
            'caractéristique malveillante dans ce '
            'fichier. Il a été automatiquement '
            'sauvegardé dans notre système de '
            'stockage sécurisé.',
            LIGHT_GREEN, GREEN_COLOR))
        story.append(Spacer(1, 0.3*cm))
        story.append(info_box(
            '<b>ℹ️  Remarque importante</b><br/>'
            'Bien que notre système soit très '
            'performant, aucun système de détection '
            'n\'est parfait à 100%. Restez vigilant '
            'et n\'exécutez que des fichiers provenant '
            'de sources fiables.',
            LIGHT_ORANGE, ORANGE))

    story.append(Spacer(1, 0.3*cm))

    # Explication simple du score
    story.append(Paragraph(
        'Comment interpréter le score de confiance ?',
        h2_style))
    score_rows = [
        ['90% - 100%', 'Très haute confiance',
         'Décision quasi-certaine'],
        ['70% - 90%', 'Haute confiance',
         'Décision fiable'],
        ['50% - 70%', 'Confiance modérée',
         'Décision probable'],
        ['< 50%', 'Faible confiance',
         'Fichier ambigu — vérification manuelle'],
    ]
    story.append(make_table(
        ['Score', 'Niveau', 'Signification'],
        score_rows, [3*cm, 5*cm, 9*cm]))

    story.append(PageBreak())

    # ══════════════════════════════════════════════════
    # SECTION 2 — ANALYSE TECHNIQUE
    # ══════════════════════════════════════════════════
    story.append(section_header(
        '2. Analyse Technique Détaillée', DARK_BLUE))
    story.append(Spacer(1, 0.3*cm))

    # ── Votes des modèles ──────────────────────────────
    story.append(Paragraph(
        '2.1  Votes des 5 modèles d\'intelligence '
        'artificielle', h2_style))
    story.append(Paragraph(
        'Chaque modèle analyse le fichier de façon '
        'indépendante et donne son verdict. La '
        'décision finale est une moyenne pondérée '
        'de tous les votes (Weighted Vote).',
        body_style))
    story.append(Spacer(1, 0.2*cm))

    if votes:
        vote_rows = []
        for v in votes:
            icon = "🔴 Malware" if v['vote'] == \
                   'Malware' else "🟢 Bénin"
            vote_rows.append([
                v['model'],
                icon,
                f"{v['proba']:.1f}%",
                f"{v['weight']:.3f}",
            ])

        story.append(make_table(
            ['Modèle', 'Verdict', 'Confiance', 'Poids'],
            vote_rows,
            [6*cm, 4*cm, 3.5*cm, 3.5*cm]))

        # Résumé des votes
        n_malware = prediction.get(
            "n_malware_votes", 0)
        n_total   = prediction.get("n_models", 0)
        story.append(Spacer(1, 0.2*cm))
        story.append(info_box(
            f'<b>Résumé des votes :</b> '
            f'{n_malware} modèle(s) sur {n_total} '
            f'ont voté "Malware" — '
            f'Score pondéré final : '
            f'{confidence:.1f}%',
            LIGHT_BLUE, ACCENT_BLUE))
    else:
        story.append(Paragraph(
            'Aucun vote disponible.', body_style))

    story.append(Spacer(1, 0.3*cm))

    # ── Explication des modèles ────────────────────────
    story.append(Paragraph(
        '2.2  Description des modèles utilisés',
        h2_style))

    models_desc = [
        ['RF (Random Forest)',
         'Forêt d\'arbres de décision parallèles',
         'Robuste au bruit'],
        ['XGBoost',
         'Arbres séquentiels correctifs',
         'Très précis sur données tabulaires'],
        ['LightGBM',
         'Gradient boosting optimisé Microsoft',
         'Rapide et performant'],
        ['CNN1D',
         'Réseau de neurones convolutif 1D',
         'Détecte des patterns locaux'],
        ['FT-Transformer',
         'Transformer adapté aux données tabulaires',
         'Interactions globales entre features'],
    ]
    story.append(make_table(
        ['Modèle', 'Description', 'Force principale'],
        models_desc,
        [3.5*cm, 7.5*cm, 6*cm]))

    story.append(PageBreak())

    # ══════════════════════════════════════════════════
    # SECTION 3 — ANALYSE STATIQUE
    # ══════════════════════════════════════════════════
    story.append(section_header(
        '3. Analyse Statique du Fichier', GREEN_COLOR))
    story.append(Spacer(1, 0.3*cm))

    story.append(Paragraph(
        'Qu\'est-ce que l\'analyse statique ?',
        h2_style))
    story.append(Paragraph(
        'L\'analyse statique examine la structure '
        'interne du fichier SANS l\'exécuter. On '
        'inspecte ses en-têtes, ses sections, ses '
        'imports de bibliothèques (DLL) et son '
        'entropie (niveau de chiffrement/compression). '
        'Cette approche est rapide et sans risque.',
        body_style))
    story.append(Spacer(1, 0.2*cm))

    if static_info:
        static_rows = [
            ['Taille du fichier',
             f"{static_info.get('size', 0)/1024:.1f} KB"],
            ['Nombre de sections',
             str(static_info.get('n_sections', 'N/A'))],
            ['Imports DLL',
             str(static_info.get('n_imports', 'N/A'))],
            ['Entropie moyenne',
             f"{static_info.get('entropy', 0):.3f}"],
            ['Architecture',
             static_info.get('arch', 'N/A')],
        ]
        story.append(make_table(
            ['Caractéristique', 'Valeur'],
            static_rows, [7*cm, 10*cm]))
    else:
        story.append(info_box(
            'ℹ️  Détails statiques non disponibles '
            'pour ce fichier.',
            LIGHT_GRAY, GRAY))

    story.append(Spacer(1, 0.3*cm))

    # ══════════════════════════════════════════════════
    # SECTION 4 — ANALYSE DYNAMIQUE
    # ══════════════════════════════════════════════════
    story.append(section_header(
        '4. Analyse Dynamique du Comportement',
        ORANGE))
    story.append(Spacer(1, 0.3*cm))

    story.append(Paragraph(
        'Qu\'est-ce que l\'analyse dynamique ?',
        h2_style))
    story.append(Paragraph(
        'L\'analyse dynamique exécute le fichier dans '
        'les résultats d’analyse fournis par VirusTotal et observe '
        'son comportement réel : processus créés, '
        'fichiers modifiés, trafic réseau, injections '
        'mémoire... Cette approche détecte les malwares '
        'qui cachent leur nature lors de l\'analyse '
        'statique.',
        body_style))
    story.append(Spacer(1, 0.2*cm))

    if dynamic_report:
        processes = dynamic_report.get(
            "processes", [])
        network   = dynamic_report.get("network", {})
        sigs      = dynamic_report.get(
            "signatures", [])

        dyn_rows = [
            ['Processus détectés',
             str(len(processes))],
            ['Connexions réseau',
             str(len(network.get("hosts", [])))],
            ['Signatures détectées',
             str(len(sigs))],
            ['Verdict VirusTotal',
             dynamic_report.get(
                 "verdict", {}).get(
                 "threat_level_human",
                 "Non disponible")],
        ]
        story.append(make_table(
            ['Indicateur', 'Valeur'],
            dyn_rows, [7*cm, 10*cm]))

        # Signatures si présentes
        if sigs:
            story.append(Spacer(1, 0.2*cm))
            story.append(Paragraph(
                'Comportements suspects détectés :',
                h3_style))
            sig_rows = [[
                s.get("name", "N/A"),
                s.get("threat_level_human", "N/A"),
                s.get("description",
                       "N/A")[:60] + "..."
                if len(s.get("description",
                              "")) > 60
                else s.get("description", "N/A")
            ] for s in sigs[:5]]

            if sig_rows:
                story.append(make_table(
                    ['Nom', 'Niveau', 'Description'],
                    sig_rows,
                    [4*cm, 3*cm, 10*cm]))
    else:
        story.append(info_box(
            'ℹ️  L\'analyse dynamique n\'a pas pu '
            'être effectuée (timeout ou service '
            'indisponible). La décision est basée '
            'uniquement sur l\'analyse statique.',
            LIGHT_ORANGE, ORANGE))

    story.append(PageBreak())

    # ══════════════════════════════════════════════════
    # SECTION 5 — STOCKAGE ET TRAÇABILITÉ
    # ══════════════════════════════════════════════════
    story.append(section_header(
        '5. Stockage et Traçabilité',
        DARK_BLUE))
    story.append(Spacer(1, 0.3*cm))

    if not is_malware:
        story.append(info_box(
            f'<b>✅ Fichier sauvegardé dans MinIO</b>'
            f'<br/>Le fichier "{filename}" a été '
            f'automatiquement sauvegardé dans notre '
            f'système de stockage sécurisé car il a '
            f'été classifié comme bénin avec une '
            f'confiance de {confidence:.1f}%.',
            LIGHT_GREEN, GREEN_COLOR))
    else:
        story.append(info_box(
            f'<b>🚫 Fichier mis en quarantaine</b>'
            f'<br/>Le fichier "{filename}" N\'a PAS '
            f'été sauvegardé. Il a été signalé comme '
            f'malveillant et ne doit pas être '
            f'exécuté.',
            LIGHT_RED, RED_COLOR))

    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(
        'Informations de traçabilité', h2_style))
    trace_rows = [
        ['Fichier analysé', filename],
        ['Hash SHA256', sha256],
        ['Date d\'analyse',
         datetime.now().strftime(
             '%d/%m/%Y à %H:%M:%S')],
        ['Verdict final', verdict],
        ['Score de confiance',
         f'{confidence:.1f}%'],
        ['Nombre de modèles', str(len(votes))],
        ['Votes malware',
         str(prediction.get(
             "n_malware_votes", 0))],
    ]
    story.append(make_table(
        ['Propriété', 'Valeur'],
        trace_rows, [5*cm, 12*cm]))

    # ══════════════════════════════════════════════════
    # PIED DE PAGE FINAL
    # ══════════════════════════════════════════════════
    story.append(Spacer(1, 0.5*cm))
    story.append(HRFlowable(
        width="100%", thickness=1, color=DARK_BLUE))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(
        'Ce rapport a été généré automatiquement par '
        'le Système Hybride de Détection de Malwares '
        '(ML+DL). Les résultats sont basés sur '
        'l\'analyse de 5 modèles d\'IA combinés via '
        'Weighted Vote. Pour toute question, '
        'contactez votre équipe de sécurité.',
        small_style))

    # ── Build ──────────────────────────────────────────
    doc.build(story,
              onFirstPage=header_footer,
              onLaterPages=header_footer)

    buffer.seek(0)
    return buffer.read()