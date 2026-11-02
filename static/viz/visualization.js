const DATA_URL = 'https://raw.githubusercontent.com/bilals12/see/main/';
const WINDOW_MS = 24 * 60 * 60 * 1000;
const MAX_GAP_MS = 15 * 60 * 1000;  // see writes every 5 min, so a longer gap means the mac was off
const REFRESH_MS = 5 * 60 * 1000;   // raw.githubusercontent.com caches for 5 min

// the greens are close, so the dash pattern tells the lines apart
const metrics = {
    keypresses:  { label: 'keypresses',   color: '#7FFF00', dash: null },
    leftclicks:  { label: 'left clicks',  color: '#90EE90', dash: '6,4' },
    rightclicks: { label: 'right clicks', color: '#98FB98', dash: '2,4' },
    mousemoves:  { label: 'mouse (m)',    color: '#00FF7F', dash: '12,4,2,4' },
};

let currentData = [];

function formatNumber(num) {
    return num.toLocaleString('en-US');
}

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
            renderChart(currentData);
        })
        .catch(error => console.error('error loading past 24 hours data:', error));
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
        }))
        .sort((a, b) => a.timestamp - b.timestamp);
}

function renderChart(data) {
    d3.select('#chart').html('');
    d3.selectAll('.tooltip').remove();
    if (data.length === 0) return;

    // the window ends at the newest point, not at the visitor's clock, so the chart is not empty while the mac is off
    const end = data[data.length - 1].timestamp;
    const start = new Date(end - WINDOW_MS);
    document.getElementById('updated').textContent =
        'last update: ' + end.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });

    // drop the lines to 0 across gaps
    const zero = time => ({ timestamp: new Date(time), keypresses: 0, mousemoves: 0, leftclicks: 0, rightclicks: 0 });
    const series = [zero(start)];
    for (const d of data) {
        const prev = series[series.length - 1].timestamp;
        if (d.timestamp - prev > MAX_GAP_MS) series.push(zero(+prev + 60000), zero(d.timestamp - 60000));
        series.push(d);
    }

    const chartContainer = d3.select('#chart');
    const margin = { top: 20, right: 20, bottom: 30, left: 50 };
    const width = (parseInt(chartContainer.style('width')) || 800) - margin.left - margin.right;
    const height = (parseInt(chartContainer.style('height')) || 400) - margin.top - margin.bottom;

    const svg = chartContainer
        .append('svg')
        .style('width', '100%')
        .style('height', '100%')
        .attr('viewBox', `0 0 ${width + margin.left + margin.right} ${height + margin.top + margin.bottom}`)
        .append('g')
        .attr('transform', `translate(${margin.left},${margin.top})`);

    const keys = Object.keys(metrics);
    const x = d3.scaleTime().domain([start, end]).range([0, width]);
    const y = d3.scaleLinear()
        .domain([0, d3.max(data, d => d3.max(keys, k => d[k])) * 1.1 || 10])
        .range([height, 0]);

    svg.append('g')
        .attr('class', 'grid')
        .call(d3.axisLeft(y).ticks(5).tickSize(-width).tickFormat(''))
        .style('stroke', '#0f0')
        .style('stroke-opacity', 0.1);
    svg.append('g')
        .attr('class', 'grid')
        .attr('transform', `translate(0,${height})`)
        .call(d3.axisBottom(x).ticks(d3.timeHour.every(1)).tickSize(-height).tickFormat(''))
        .style('stroke', '#0f0')
        .style('stroke-opacity', 0.1);

    svg.append('g')
        .attr('transform', `translate(0,${height})`)
        .call(d3.axisBottom(x).ticks(d3.timeHour.every(3)).tickFormat(d3.timeFormat('%-I%p')).tickSizeOuter(0))
        .style('color', '#0f0')
        .style('font-family', 'monospace')
        .style('font-size', '12px');
    svg.append('g')
        .call(d3.axisLeft(y).ticks(5))
        .style('color', '#0f0')
        .style('font-family', 'monospace')
        .style('font-size', '12px');

    for (const [key, m] of Object.entries(metrics)) {
        svg.append('path')
            .datum(series)
            .attr('fill', 'none')
            .attr('stroke', m.color)
            .attr('stroke-width', 2)
            .attr('stroke-dasharray', m.dash)
            .attr('d', d3.line().x(d => x(d.timestamp)).y(d => y(d[key])).curve(d3.curveMonotoneX));
    }

    const tooltip = d3.select('body').append('div').attr('class', 'tooltip').style('opacity', 0);
    const overlay = svg.append('rect')
        .attr('width', width)
        .attr('height', height)
        .attr('fill', 'none')
        .style('pointer-events', 'all');
    // the line and the dots sit on top of the overlay; without pointer-events: none they steal the mouse and the tooltip flickers
    const verticalLine = svg.append('line')
        .attr('y1', 0)
        .attr('y2', height)
        .style('stroke', '#0f0')
        .style('pointer-events', 'none')
        .style('opacity', 0);
    const dots = Object.fromEntries(Object.entries(metrics).map(([key, m]) => [key, svg.append('circle')
        .attr('r', 5)
        .attr('fill', m.color)
        .attr('stroke', '#000')
        .attr('stroke-width', 1.5)
        .style('pointer-events', 'none')
        .style('opacity', 0)]));
    const bisect = d3.bisector(d => d.timestamp).left;

    overlay.on('mousemove', event => {
        const time = x.invert(d3.pointer(event)[0]);
        const i = bisect(data, time, 1);
        const d0 = data[i - 1];
        const d1 = data[i] || d0;
        const d = time - d0.timestamp > d1.timestamp - time ? d1 : d0;

        const flip = x(d.timestamp) > width / 2;
        verticalLine.attr('x1', x(d.timestamp)).attr('x2', x(d.timestamp)).style('opacity', 0.7);
        for (const key of keys) dots[key].attr('cx', x(d.timestamp)).attr('cy', y(d[key])).style('opacity', 1);
        tooltip
            .style('opacity', 0.9)
            .style('left', `${event.pageX + (flip ? -15 : 15)}px`)
            .style('top', `${event.pageY - 10}px`)
            .style('transform', flip ? 'translateX(-100%)' : null)
            .html(`
                <div style="font-weight:bold;margin-bottom:5px;border-bottom:1px solid #0f0;">
                    ${d.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </div>
                <div>keypresses: ${formatNumber(d.keypresses)}</div>
                <div>mouse: ${d.mousemoves.toFixed(1)}m</div>
                <div>left clicks: ${formatNumber(d.leftclicks)}</div>
                <div>right clicks: ${formatNumber(d.rightclicks)}</div>
            `);
    });

    overlay.on('mouseout', () => {
        tooltip.style('opacity', 0);
        verticalLine.style('opacity', 0);
        for (const key of keys) dots[key].style('opacity', 0);
    });
}

d3.select('#legend').html(Object.values(metrics).map(m => `
    <span><svg width="24" height="8"><line x1="0" y1="4" x2="24" y2="4"
        stroke="${m.color}" stroke-width="2" stroke-dasharray="${m.dash || ''}"/></svg> ${m.label}</span>
`).join(''));

loadData();
setInterval(loadData, REFRESH_MS);

window.addEventListener('resize', () => {
    clearTimeout(window.resizeTimer);
    window.resizeTimer = setTimeout(() => renderChart(currentData), 250);
});
