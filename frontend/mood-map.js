// Shared mood mapping utilities
const moodMap = [
    { n: 1, label: '开心', emoji: '😊' },
    { n: 2, label: '平静', emoji: '😌' },
    { n: 3, label: '焦虑', emoji: '😟' },
    { n: 4, label: '难过', emoji: '😢' },
    { n: 5, label: '愤怒', emoji: '😡' },
    { n: 6, label: '疲惫', emoji: '😴' },
    { n: 7, label: '孤独', emoji: '😔' },
];

function numberToLabel(n){ const it = moodMap.find(x=>x.n===Number(n)); return it?it.label:''; }
function numberToEmoji(n){ const it = moodMap.find(x=>x.n===Number(n)); return it?it.emoji:''; }
function labelToEmoji(label){ const it = moodMap.find(x=>x.label===label); return it?it.emoji:''; }
function emojiToLabel(emoji){ const it = moodMap.find(x=>x.emoji===emoji); return it?it.label:''; }

// expose on window for simple inclusion in static pages
window.moodMap = moodMap;
window.numberToLabel = numberToLabel;
window.numberToEmoji = numberToEmoji;
window.labelToEmoji = labelToEmoji;
window.emojiToLabel = emojiToLabel;
