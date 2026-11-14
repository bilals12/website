// node checks/particle-reactor.js [shortcode file]
// runs code from layouts/shortcodes/particle-reactor.html with fake clocks and fake particles
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const src = fs.readFileSync(process.argv[2] || path.join(__dirname, '../layouts/shortcodes/particle-reactor.html'), 'utf8');
const between = (start, end) => src.slice(src.indexOf(start), src.indexOf(end, src.indexOf(start)));

// 1. the loop: the same steps per second at any refresh rate
const stepMs = eval(src.match(/const STEP_MS = ([^;]+);/)[1]);
const loop = between('    let visible = false;', "    window.addEventListener('resize'");
for (const hz of [30, 60, 120, 144]) {
    let steps = 0;
    let draws = 0;
    const queue = [];
    const animate = new Function('STEP_MS', 'step', 'draw', 'requestAnimationFrame',
        `${loop}; visible = true; running = true; return animate;`)(stepMs, () => steps++, () => draws++, cb => queue.push(cb));
    queue.push(animate);
    for (let t = 0; t < 10000;) {
        t += 1000 / hz;
        queue.shift()(t);
    }
    assert.ok(Math.abs(steps / 10 - 1000 / stepMs) < 1, `${hz} Hz: ${steps / 10} steps/s, expected ${1000 / stepMs}`);
    assert.ok(draws / 10 <= Math.min(hz, 1000 / stepMs) + 1, `${hz} Hz: ${draws / 10} draws/s`);
}

// 2. the air around the sphere: the real Particle class
const CONFIG = eval(`(${between('{\n        width:', '    };\n')}})`);
const a = CONFIG.bubbleRadius * 1.5;
const U = -CONFIG.width / (CONFIG.particleCrossTime * 60) * CONFIG.particleSpeedMultiplier;
const flow = { cx: 0, cy: 0, px: 0, py: 0, clock: 0 };
const make = code => new Function('CONFIG', 'OUTLINE_RADIUS', 'flow', 'STREAM_SPEED', code)(CONFIG, a, flow, U);
const Particle = make(`${between('    class Particle {', '    // Canvas for particles')}; return Particle;`);
// a version without the clock (a rigid wake) gets one that never ticks, so the motion test can fail on it
const advanceWakeClock = src.includes('function advanceWakeClock(')
    ? make(`${between('    function advanceWakeClock(', '\n    }')}\n    }; return advanceWakeClock;`)
    : () => {};
const reset = () => Object.assign(flow, { cx: 0, cy: 0, px: 0, py: 0, clock: 0 });

// the velocity field, measured as a tiny step
const velocity = (x, y, vx = 0, vy = 0) => {
    const p = new Particle(true);
    Object.assign(p, { x, y });
    p.flowStep(0, 0, vx, vy, 1e-6);
    return [(p.x - x) / 1e-6, (p.y - y) / 1e-6];
};
let stagnation = null;
for (let x = a * 1.0001; x < 1.5 * a && stagnation === null; x += 0.1) {
    if (velocity(x, 0.01)[0] <= 0) stagnation = x / a;
}
assert.ok(stagnation !== null && stagnation < 1.1, `the air comes to rest just in front of the sphere: ${stagnation}`);
const top = velocity(0, -a * 1.0001)[0] / U;
assert.ok(top > 1.2 && top < 1.5, `the air over the top moves at ${top.toFixed(2)} times the stream`);
for (const [vx, vy] of [[0, 0], [0, 20], [15, -10], [-30, 5]]) {
    for (let angle = 0; angle < 2 * Math.PI; angle += 0.1) {
        const n = [Math.cos(angle), Math.sin(angle)];
        const [u, v] = velocity(a * 1.0001 * n[0], a * 1.0001 * n[1], vx, vy);
        assert.ok((u - vx) * n[0] + (v - vy) * n[1] > -0.05,
            `sphere moving (${vx}, ${vy}): air flows into it at angle ${angle.toFixed(1)}`);
    }
}

// one stream past a still sphere, recorded at every substep
function stream(y0) {
    reset();
    const p = new Particle(true);
    Object.assign(p, { x: 1100, y: y0, through: false });
    const points = [];
    const record = p.record;
    p.record = function (length) {
        points.push([this.x, this.y]);
        record.call(this, length);
    };
    let steps = 0;
    for (; p.x > -1100 && steps < 2000; steps++) p.update();
    return { points, steps, end: p.y };
}
const yAt = (points, x) => points.reduce((best, q) => (Math.abs(q[0] - x) < Math.abs(best[0] - x) ? q : best))[1];

// the back is not a mirror of the front: behind the sphere the streams stay apart (the wake)
for (const f of [0.2, 0.5, 1.0]) {
    const { points } = stream(f * a);
    const front = Math.abs(yAt(points, 2 * a) - f * a);
    const back = Math.abs(yAt(points, -2 * a) - f * a);
    assert.ok(back > 3 * front, `a stream ${f}a off the axis: ${front.toFixed(1)} px off its line 2a in front, ${back.toFixed(1)} px 2a behind`);
}

// the wake is an egg behind the sphere: the stream along its edge narrows steadily from the shoulder and is
// about as wide as the sphere (no bulge, no dip behind the shoulder)
{
    const { points } = stream(2);
    const widths = [-0.5, -1, -1.5, -2, -2.5, -3, -3.5].map(x => Math.abs(yAt(points, x * a)) / a);
    let narrowest = Infinity;
    for (const w of widths) {
        narrowest = Math.min(narrowest, w);
        assert.ok(w - narrowest < 0.05, `the wake widens again behind the sphere: ${widths.map(v => v.toFixed(2)).join(' ')}`);
    }
    assert.ok(Math.max(...widths) < 1.2, `the wake is wider than the sphere: ${widths.map(v => v.toFixed(2)).join(' ')}`);
}

// every stream, 1 px apart: smooth, never flung (a point sink flings air that comes close), and none stalls
{
    let sharpestBend = 0;
    let fastest = 0;
    let slowest = 0;
    for (let y0 = -240; y0 <= 240; y0++) {
        const { points, steps } = stream(y0);
        slowest = Math.max(slowest, steps);
        for (let i = 2; i < points.length; i++) {
            const [p0, p1, p2] = [points[i - 2], points[i - 1], points[i]];
            sharpestBend = Math.max(sharpestBend, Math.hypot(p2[0] - 2 * p1[0] + p0[0], p2[1] - 2 * p1[1] + p0[1]));
            fastest = Math.max(fastest, Math.hypot(p2[0] - p1[0], p2[1] - p1[1]) / (Math.abs(U) / CONFIG.flowSubsteps));
        }
    }
    assert.ok(sharpestBend < 6, `the trails bend by up to ${sharpestBend.toFixed(1)} px`);
    assert.ok(fastest < 1.6, `air is flung at ${fastest.toFixed(2)} times the stream`);
    assert.ok(slowest < 200, `a particle stalls: the slowest took ${slowest} steps`);
}

// a scroll: the sphere eases toward targets that change every second; and one big jump with air already around it
function moving(moveSphere, startX = () => 1100) {
    let zigzags = 0;
    for (let y0 = -240; y0 <= 240; y0 += 3) {
        reset();
        const p = new Particle(true);
        Object.assign(p, { x: startX(y0), y: y0, through: false });
        const ys = [];
        const record = p.record;
        p.record = function (length) {
            ys.push(this.y);
            record.call(this, length);
        };
        let k = 0;
        for (; p.x > -1100 && k < 2000; k++) {
            flow.px = flow.cx;
            flow.py = flow.cy;
            moveSphere(k);
            p.update();
        }
        assert.ok(Number.isFinite(p.x) && Number.isFinite(p.y), `y0 ${y0}: position is not a number`);
        assert.ok(k < 2000, `y0 ${y0}: the particle never left the screen`);
        for (let i = 2; i < ys.length; i++) {
            const d1 = ys[i - 1] - ys[i - 2];
            const d2 = ys[i] - ys[i - 1];
            if (d1 * d2 < 0 && Math.min(Math.abs(d1), Math.abs(d2)) > 5) zigzags++;
        }
    }
    return zigzags;
}
// the sphere follows the fingers directly: a drag along a circle at a normal finger speed (~1900 canvas units/s),
// fast flicks back and forth, and mouse-wheel notches that jump it ~87 canvas units in one step
const dragged = moving(k => {
    const t = k / 120 * 2 * Math.PI;
    flow.cx = 300 * Math.sin(t);
    flow.cy = 120 * Math.sin(2 * t);
});
const flicked = moving(k => {
    flow.cx = Math.max(-450, Math.min(450, flow.cx + (Math.floor(k / 20) % 2 ? 45 : -45)));
});
const notched = moving(k => {
    if (k % 30 === 0) flow.cy = flow.cy > 0 ? -87 : 87;
});
assert.strictEqual(dragged, 0, `dragged sphere: ${dragged} zigzags in the trails`);
assert.strictEqual(flicked, 0, `flicked sphere: ${flicked} zigzags in the trails`);
assert.strictEqual(notched, 0, `wheel-notched sphere: ${notched} zigzags in the trails`);

// the wake is alive but calm: it breathes and sways slowly. Over one breath its end moves visibly, yet the air
// in the wake changes little from one step to the next, and the whole page shows no jolts at step boundaries
{
    reset();
    const probe = [-2.6 * a, 0.5 * a];
    let lowest = Infinity;
    let highest = -Infinity;
    let biggestChange = 0;
    let before = velocity(...probe);
    for (let k = 0; k < 400; k++) {
        advanceWakeClock(0, 0);
        const now = velocity(...probe);
        lowest = Math.min(lowest, now[1]);
        highest = Math.max(highest, now[1]);
        biggestChange = Math.max(biggestChange, Math.hypot(now[0] - before[0], now[1] - before[1]));
        before = now;
    }
    const swing = highest - lowest;
    assert.ok(swing > 0.05 * Math.abs(U), `the wake does not move: the air behind the sphere varies by ${swing.toFixed(2)} px/step`);
    assert.ok(biggestChange < 0.05 * swing, `the wake jumps: ${biggestChange.toFixed(2)} px/step in one step, ${swing.toFixed(2)} in all`);

    reset();
    let seed = 1;
    const random = Math.random;
    Math.random = () => (seed = (seed * 16807) % 2147483647) / 2147483647;
    const perStep = CONFIG.particleCount / (CONFIG.particleCrossTime * 60);
    const bends = { boundary: [], inside: [] };
    let fastest = 0;
    let particles = [];
    let spawn = 0;
    for (let k = 0; k < 500; k++) {
        flow.px = flow.cx;
        flow.py = flow.cy;
        advanceWakeClock(0, 0);
        for (spawn += perStep; spawn >= 1; spawn--) particles.push(Object.assign(new Particle(true), { through: false }));
        for (const p of particles) {
            const points = [];
            const record = p.record;
            p.record = function (length) {
                points.push([this.x, this.y]);
                record.call(this, length);
            };
            p.update();
            p.record = record;
            const all = [p.last2, p.last1, ...points].filter(Boolean);
            for (let i = 2; i < all.length && k > 150; i++) {
                const bend = Math.hypot(all[i][0] - 2 * all[i - 1][0] + all[i - 2][0], all[i][1] - 2 * all[i - 1][1] + all[i - 2][1]);
                const inWake = all[i - 1][0] < 0 && all[i - 1][0] > -4 * a && Math.abs(all[i - 1][1]) < 1.3 * a;
                if (inWake) (i - (all.length - points.length) === 0 ? bends.boundary : bends.inside).push(bend);
                fastest = Math.max(fastest, Math.hypot(all[i][0] - all[i - 1][0], all[i][1] - all[i - 1][1]) / (Math.abs(U) / CONFIG.flowSubsteps));
            }
            [p.last2, p.last1] = points.slice(-2);
        }
        particles = particles.filter(p => p.x > -CONFIG.width / 2 - 100);
    }
    Math.random = random;
    const p99 = arr => [...arr].sort((x, y) => x - y)[Math.floor(arr.length * 0.99)];
    assert.ok(p99(bends.boundary) < 1.3 * p99(bends.inside) + 0.1,
        `the wake jolts at step boundaries: ${p99(bends.boundary).toFixed(2)} px against ${p99(bends.inside).toFixed(2)} px`);
    const sharpest = bends.inside.concat(bends.boundary).reduce((x, y) => Math.max(x, y), 0);
    assert.ok(sharpest < 6, `the trails in the moving wake bend by up to ${sharpest.toFixed(1)} px`);
    assert.ok(fastest < 1.6, `air is flung at ${fastest.toFixed(2)} times the stream while the wake moves`);
    assert.ok(particles.every(p => p.x < CONFIG.width / 2 + 200), 'a particle stalls');
}

console.log(`ok: ${Math.round(1000 / stepMs)} steps/s at 30-144 Hz; air at rest at ${stagnation.toFixed(2)}a, ${top.toFixed(2)} U ` +
    `over the top, never into the sphere; an egg-shaped wake behind it, not in front, that breathes and sways ` +
    `slowly; smooth, never flung; ` +
    `no zigzags when the sphere moves`);
