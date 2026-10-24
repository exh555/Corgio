(function () {
    try {
        if (!localStorage.getItem('corgio_pembroke_default_v1')) {
            localStorage.setItem('corgio_palette', 'pembroke');
            localStorage.setItem('corgio_theme', 'light');
            localStorage.setItem('corgio_pembroke_default_v1', '1');
        }
        var rawPalette = localStorage.getItem('corgio_palette') || 'pembroke';
        var cleanPalette = (rawPalette === 'github' || rawPalette === 'slate') ? 'github' : 'pembroke';
        var savedTheme = localStorage.getItem('corgio_theme') || 'light';
        var effectiveMode = savedTheme;
        if (savedTheme === 'system') {
            effectiveMode = window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
        }
        document.documentElement.setAttribute('data-palette', cleanPalette);
        document.documentElement.setAttribute('data-mode', effectiveMode === 'dark' ? 'dark' : 'light');
    } catch (e) {}
})();
