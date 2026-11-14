const { url: DATA_URL, liveMinutes } = document.getElementById('activity-visualization').dataset;
const INTERVAL_MS = 5 * 60 * 1000;  // see writes one row every 5 min
const REFRESH_MS = 5 * 60 * 1000;   // raw.githubusercontent.com caches for 5 min
const LIVE_MS = liveMinutes * 60 * 1000;
const SPARK_LINES = 5;              // text lines per sparkline
const MIN_FONT_PX = 9;
const MAX_HEATMAP_FONT_PX = 18;
const BLOCKS = ' ▁▂▃▄▅▆▇█';
const SHADES = ['··', '░░', '▒▒', '▓▓', '██'];
const KEYS = ['keypresses', 'mousemoves', 'leftclicks', 'rightclicks', 'clicks'];

// one sparkline per metric, each with its own scale: keypresses are ~100x the clicks and meters
const rows = [
    { key: 'keypresses', label: 'keypresses', unit: '' },
    { key: 'clicks',     label: 'clicks',     unit: '' },
    { key: 'mousemoves', label: 'mouse',      unit: 'm' },
];

const chart = document.getElementById('chart');
const heatmap = document.getElementById('heatmap');
const tooltip = document.body.appendChild(document.createElement('div'));
tooltip.className = 'tooltip';

let currentData = [];
let currentHistory = [];
let dayBins = [];
let weekCells = [];

function formatNumber(num) {
    return num.toLocaleString('en-US', { maximumFractionDigits: 1 });
}

const hourLabel = h => (h % 12 || 12) + (h % 24 < 12 ? 'am' : 'pm');
const formatTime = t => t.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' }).toLowerCase();
const duration = ms => {
    const m = Math.round(ms / 60000);
    return m >= 60 ? `${Math.floor(m / 60)}h ${m % 60}m` : `${m}m`;
};

function fetchCSV(file) {
    return fetch(DATA_URL + file).then(response => {
        if (!response.ok) throw new Error(`${file}: HTTP ${response.status}`);
        return response.text();
    });
}

function loadData() {
    fetchCSV('cumulative_data.csv')
        .then(text => {
            const [keypresses, mousemoves, leftclicks, rightclicks] = text.split('\n')[1].split(',');
            document.getElementById('keypresses').textContent = formatNumber(parseInt(keypresses) || 0);
            document.getElementById('mousemoves').textContent = formatNumber((parseFloat(mousemoves) || 0) / 1000) + 'km';
            document.getElementById('leftclicks').textContent = formatNumber(parseInt(leftclicks) || 0);
            document.getElementById('rightclicks').textContent = formatNumber(parseInt(rightclicks) || 0);
        })
        .catch(error => console.error('error loading cumulative data:', error));

    fetchCSV('past_24_hours_data.csv')
        .then(text => {
            currentData = parseCSV(text);
            renderDay(currentData);
        })
        .catch(error => console.error('error loading past 24 hours data:', error));

    fetchCSV('history.csv')
        .then(text => {
            currentHistory = parseCSV(text);
            renderWeek(currentHistory);
        })
        .catch(error => {
            document.getElementById('week').hidden = true;
            console.error('error loading history:', error);
        });
}

// skips the header and the trailing `cumulative,...` row; see writes rows in ring-buffer order
function parseCSV(text) {
    return text.split('\n')
        .map(line => line.split(','))
        .filter(cols => cols.length === 6 && /^\d+$/.test(cols[0]))
        .map(([timestamp, keypresses, mousemoves, leftclicks, rightclicks]) => ({
            timestamp: new Date(parseInt(timestamp) * 1000),
            keypresses: parseInt(keypresses) || 0,
            mousemoves: parseFloat(mousemoves) || 0,
            leftclicks: parseInt(leftclicks) || 0,
            rightclicks: parseInt(rightclicks) || 0,
            clicks: (parseInt(leftclicks) || 0) + (parseInt(rightclicks) || 0),
        }))
        .sort((a, b) => a.timestamp - b.timestamp);
}

// end of the local-time bin that holds `time`; local, so 30- and 60-minute bins line up in zones like UTC+5:30
function binEnd(time, minutes) {
    const t = new Date(time);
    t.setMinutes(Math.ceil((t.getMinutes() + t.getSeconds() / 60) / minutes) * minutes, 0, 0);
    return +t;
}

// width of one character as a fraction of the font size; each glyph sits in a 1ch span
function charRatio(el) {
    const probe = el.appendChild(document.createElement('span'));
    probe.style.cssText = 'position:absolute;visibility:hidden;font-size:100px;white-space:pre';
    probe.textContent = '0'.repeat(10);
    const ratio = probe.getBoundingClientRect().width / 1000;
    probe.remove();
    return ratio;
}

// font size in px that makes `columns` characters fill the content width of `el`
function fitFont(el, columns) {
    const style = getComputedStyle(el);
    const width = el.clientWidth - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight);
    return Math.floor(width / columns / charRatio(el) * 10) / 10;
}

function renderDay(data) {
    if (data.length === 0) return;
    const last = data[data.length - 1].timestamp;
    renderLive(last);
    document.getElementById('summary').textContent = summarize(data);

    // the font size makes the bars fill the width; wider bins on narrow screens keep the text readable
    const minutes = [15, 30, 60].find(m => fitFont(chart, 1440 / m) >= MIN_FONT_PX) || 60;
    const n = 1440 / minutes;
    const fontSize = `${fitFont(chart, n)}px`;

    const sums = new Map();
    for (const d of data) {
        const end = binEnd(d.timestamp, minutes);
        const bin = sums.get(end) || Object.fromEntries(KEYS.map(k => [k, 0]));
        for (const k of KEYS) bin[k] += d[k];
        sums.set(end, bin);
    }
    const lastEnd = binEnd(last, minutes);
    dayBins = Array.from({ length: n }, (_, i) => {
        const end = lastEnd - (n - 1 - i) * minutes * 60000;
        return { start: new Date(end - minutes * 60000), end: new Date(end), ...sums.get(end) };
    });

    const html = [];
    for (const row of rows) {
        const values = dayBins.map(b => b[row.key] || 0);
        const max = Math.max(...values) || 1;
        const total = values.reduce((a, b) => a + b, 0);
        const eighths = values.map(v => v > 0 ? Math.max(1, Math.round(v / max * SPARK_LINES * 8)) : 0);
        const lines = [];
        for (let line = SPARK_LINES - 1; line >= 0; line--) {
            lines.push(eighths.map((e, i) => `<span data-i="${i}">${BLOCKS[Math.min(8, Math.max(0, e - line * 8))]}</span>`).join(''));
        }
        html.push(`<div class="spark-label"><span>${row.label}</span><span>${formatNumber(total)}${row.unit}</span></div>`);
        html.push(`<div class="spark" style="font-size:${fontSize}">${lines.join('\n')}</div>`);
    }
    html.push(`<div class="spark axis" style="font-size:${fontSize}">${axis(dayBins.map(b => b.start), 1)}</div>`);
    chart.innerHTML = html.join('');
}

// a label at each local hour that is a multiple of 3, where it fits; `width` is the characters per column
function axis(starts, width) {
    const chars = Array(starts.length * width).fill(' ');
    starts.forEach((t, i) => {
        if (t.getMinutes() !== 0 || t.getHours() % 3 !== 0) return;
        const label = hourLabel(t.getHours());
        const at = i * width;
        if (at + label.length > chars.length || chars.slice(Math.max(0, at - 1), at + label.length).some(c => c !== ' ')) return;
        chars.splice(at, label.length, ...label);
    });
    return chars.join('');
}

function summarize(data) {
    const active = data.filter(d => d.keypresses || d.clicks || d.mousemoves);
    if (active.length === 0) return 'no activity in the last 24 hours';
    const perHour = new Map();
    for (const d of data) {
        const hour = new Date(d.timestamp - INTERVAL_MS / 2);
        hour.setMinutes(0, 0, 0);
        perHour.set(+hour, (perHour.get(+hour) || 0) + d.keypresses);
    }
    const [busiest] = [...perHour].reduce((a, b) => (b[1] > a[1] ? b : a));
    let longestBreak = 0;
    for (let i = 1; i < active.length; i++) {
        longestBreak = Math.max(longestBreak, active[i].timestamp - active[i - 1].timestamp - INTERVAL_MS);
    }
    return `active ${duration(active.length * INTERVAL_MS)} · busiest hour ${hourLabel(new Date(busiest).getHours())}` +
        ` · longest break ${duration(longestBreak)}`;
}

function renderLive(last) {
    const live = Date.now() - last < LIVE_MS;
    const el = document.getElementById('live');
    el.title = 'last update: ' + last.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }).toLowerCase();
    el.innerHTML = live
        ? '<span class="live-dot">●</span> live'
        : 'idle since ' + last.toLocaleString([], { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }).toLowerCase();
}

function renderWeek(history) {
    if (history.length === 0) return;
    const perHour = new Map();
    for (const d of history) {
        const t = new Date(d.timestamp - INTERVAL_MS / 2);
        const key = `${t.toDateString()}|${t.getHours()}`;
        perHour.set(key, (perHour.get(key) || 0) + d.keypresses);
    }
    // levels by quartile of the hours with activity, as in the GitHub contribution graph
    const sorted = [...perHour.values()].filter(v => v > 0).sort((a, b) => a - b);
    const quartiles = [0.25, 0.5, 0.75].map(p => sorted[Math.floor(p * (sorted.length - 1))] || 0);
    const level = v => (v === 0 ? 0 : 1 + quartiles.filter(q => v > q).length);

    // the week ends on the day of the newest row, as the 24-hour chart does
    const lastDay = new Date(history[history.length - 1].timestamp);
    lastDay.setHours(0, 0, 0, 0);
    const hourStarts = Array.from({ length: 24 }, (_, h) => new Date(2000, 0, 1, h));
    const lines = [' '.repeat(7) + axis(hourStarts, 2)];
    weekCells = [];
    for (let i = 6; i >= 0; i--) {
        const day = new Date(lastDay);
        day.setDate(day.getDate() - i);
        let line = `${day.toLocaleDateString([], { weekday: 'short' }).toLowerCase()} ${day.getDate()}`.padEnd(7);
        for (let h = 0; h < 24; h++) {
            const value = perHour.get(`${day.toDateString()}|${h}`);
            const c = weekCells.push({ day, h, value }) - 1;
            line += value === undefined
                ? `<span data-c="${c}">  </span>`
                : `<span data-c="${c}" class="l${level(value)}">${SHADES[level(value)]}</span>`;
        }
        lines.push(line);
    }
    document.getElementById('week').hidden = false;
    heatmap.style.fontSize = `${Math.min(MAX_HEATMAP_FONT_PX, fitFont(heatmap, 7 + 24 * 2))}px`;
    heatmap.innerHTML = lines.join('\n');
}

function showTooltip(event, html) {
    const flip = event.clientX > window.innerWidth / 2;
    tooltip.innerHTML = html;
    tooltip.style.left = `${event.pageX + (flip ? -15 : 15)}px`;
    tooltip.style.top = `${event.pageY + 15}px`;
    tooltip.style.transform = flip ? 'translateX(-100%)' : '';
    tooltip.style.opacity = 1;
}

function hover(container, attr, describe) {
    container.addEventListener('mouseover', event => {
        const id = event.target.dataset && event.target.dataset[attr];
        if (id === undefined) return;
        container.querySelectorAll('.hl').forEach(el => el.classList.remove('hl'));
        container.querySelectorAll(`[data-${attr}="${id}"]`).forEach(el => el.classList.add('hl'));
        showTooltip(event, describe(+id));
    });
    container.addEventListener('mouseleave', () => {
        tooltip.style.opacity = 0;
        container.querySelectorAll('.hl').forEach(el => el.classList.remove('hl'));
    });
}

hover(chart, 'i', i => {
    const b = dayBins[i];
    const head = `<div class="tooltip-head">${formatTime(b.start)} - ${formatTime(b.end)}</div>`;
    if (b.keypresses === undefined) return head + '<div>no data</div>';
    return head + `
        <div>keypresses: ${formatNumber(b.keypresses)}</div>
        <div>clicks: ${formatNumber(b.leftclicks)} left, ${formatNumber(b.rightclicks)} right</div>
        <div>mouse: ${formatNumber(b.mousemoves)}m</div>`;
});

hover(heatmap, 'c', c => {
    const { day, h, value } = weekCells[c];
    const date = day.toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric' }).toLowerCase();
    return `<div class="tooltip-head">${date}, ${hourLabel(h)} - ${hourLabel(h + 1)}</div>` +
        `<div>${value === undefined ? 'no data' : formatNumber(value) + ' keypresses'}</div>`;
});

loadData();
setInterval(loadData, REFRESH_MS);

window.addEventListener('resize', () => {
    clearTimeout(window.resizeTimer);
    window.resizeTimer = setTimeout(() => {
        renderDay(currentData);
        renderWeek(currentHistory);
    }, 250);
});
