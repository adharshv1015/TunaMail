const fs = require('fs');
const path = require('path');

const COMPONENTS_DIR = path.join(__dirname, 'src', 'components');

const replacements = [
  { match: /text-\[var\(--tm-text\)\]0/g, replace: 'text-[var(--tm-text-secondary)]' },
];

function processDirectory(dir) {
  const files = fs.readdirSync(dir);
  for (const file of files) {
    const fullPath = path.join(dir, file);
    if (fs.statSync(fullPath).isDirectory()) {
      processDirectory(fullPath);
    } else if (fullPath.endsWith('.jsx')) {
      if (file === 'Topbar.jsx') continue; // Skip Topbar.jsx because its logo text must stay white

      let content = fs.readFileSync(fullPath, 'utf8');
      let originalContent = content;
      
      for (const r of replacements) {
        content = content.replace(r.match, r.replace);
      }
      
      if (content !== originalContent) {
        fs.writeFileSync(fullPath, content, 'utf8');
        console.log(`Updated text-white: ${fullPath}`);
      }
    }
  }
}

processDirectory(COMPONENTS_DIR);
console.log('text-white replacements complete.');
