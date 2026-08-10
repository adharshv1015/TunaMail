const fs = require('fs');
const path = require('path');

const file = path.join(__dirname, 'EmailDetail.jsx');
let content = fs.readFileSync(file, 'utf8');

// 1. Add imports
content = content.replace(
  'import ContentAnalysisCard from "./email/ContentAnalysisCard";',
  'import ContentAnalysisCard from "./email/ContentAnalysisCard";\nimport URLIntelligence from "./email/URLIntelligence";\nimport WhoisAnalysis from "./email/WhoisAnalysis";\nimport AttachmentAnalysis from "./email/AttachmentAnalysis";\nimport TrustAnalysis from "./email/TrustAnalysis";'
);

// 2. Replace URL, WHOIS, Attachments, Trust sections
const startMarker = '{/* ===================================================== */}\n      {/* URL ANALYSIS */}';
const endMarker = '{/* ===================================================== */}\n      {/* ARE REASONING */}';

const startIndex = content.indexOf(startMarker);
const endIndex = content.indexOf(endMarker);

if (startIndex !== -1 && endIndex !== -1) {
  const replacement = `      <URLIntelligence urlAnalysis={urlAnalysis} />
      <WhoisAnalysis whois={whois} />
      <AttachmentAnalysis attachmentData={attachment} rawAttachments={attachments} />
      <TrustAnalysis trust={trust} />

      `;
  content = content.substring(0, startIndex) + replacement + content.substring(endIndex);
}

// 3. Remove all old helper components from bottom
// UrlCard, WhoisField, AttachmentCard, EmptyState, SectionHeader, formatBytes
// The only one left we need is EvidenceColumn.
const urlStart = '/* ========================================================= */\n/* URL CARD */';
const evidenceStart = '/* ========================================================= */\n/* EVIDENCE COLUMN */';

const evidenceIndex = content.indexOf(evidenceStart);

if (evidenceIndex !== -1) {
  // We can just keep EvidenceColumn and delete everything after it, or properly extract EvidenceColumn in Phase 5 anyway.
  // Let's just do Phase 5 extraction now to clean up completely? No, Phase 5 is next.
  // Wait, SectionHeader and EmptyState are AT THE BOTTOM, after EvidenceColumn!
  // I'll extract them out completely by chopping off from SectionHeader down.
  // Wait, SectionHeader was already removed in my last script? No, I only removed AuthItem and BooleanItem!
  const sectionHeaderStart = '/* ========================================================= */\n/* SECTION HEADER */';
  const headerIndex = content.indexOf(sectionHeaderStart);
  
  if (headerIndex !== -1) {
    // Actually, EvidenceColumn is before EmptyState.
    // Let's just remove the UrlCard, WhoisField, AttachmentCard blocks.
    const urlIndex = content.indexOf(urlStart);
    if (urlIndex !== -1 && evidenceIndex !== -1 && evidenceIndex > urlIndex) {
      content = content.substring(0, urlIndex) + content.substring(evidenceIndex);
    }
    
    // Now remove SectionHeader, EmptyState, formatBytes. They might be scattered.
    // To avoid breaking anything, I'll let them sit there since they won't harm anything if unused,
    // OR I can just use a regex/substring to cut them out.
    // Let's just keep them until Phase 5 where we replace the rest of the file completely!
  }
}

fs.writeFileSync(file, content);
console.log('Successfully updated EmailDetail.jsx Phase 4');
