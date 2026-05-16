function extractDOMFeatures() {
    const url = window.location.href;
    const hostname = window.location.hostname;
    
    // Count all hyperlinks
    const allLinks = document.querySelectorAll('a[href]');
    const nb_hyperlinks = allLinks.length;
    
    // Count internal vs external links
    let intLinks = 0, extLinks = 0, nullLinks = 0;
    allLinks.forEach(link => {
        const href = link.getAttribute('href');
        if (!href || href === '#' || href.startsWith('javascript:')) {
            nullLinks++;
        } else if (href.includes(hostname)) {
            intLinks++;
        } else if (href.startsWith('http')) {
            extLinks++;
        }
    });
    
    const total = nb_hyperlinks || 1;
    
    // Check for iframes
    const iframes = document.querySelectorAll('iframe');
    
    // Check for login forms
    const forms = document.querySelectorAll('form');
    let login_form = 0;
    forms.forEach(form => {
        const formText = form.innerHTML.toLowerCase();
        if (formText.includes('password') || 
            formText.includes('login') || 
            formText.includes('signin')) {
            login_form = 1;
        }
    });
    
    // Check external favicon
    const favicon = document.querySelector('link[rel*="icon"]');
    let external_favicon = 0;
    if (favicon && favicon.href && !favicon.href.includes(hostname)) {
        external_favicon = 1;
    }
    
    // Count external scripts
    const scripts = document.querySelectorAll('script[src]');
    let links_in_tags = 0;
    scripts.forEach(s => {
        if (!s.src.includes(hostname)) links_in_tags++;
    });

    // Check for suspicious JS
    const bodyHTML = document.body ? document.body.innerHTML.toLowerCase() : '';
    const onmouseover = bodyHTML.includes('onmouseover') ? 1 : 0;
    const right_clic = bodyHTML.includes('contextmenu') ? 1 : 0;
    const popup_window = bodyHTML.includes('window.open') ? 1 : 0;
    
    // Check title
    const title = document.title || '';
    const empty_title = title.trim() === '' ? 1 : 0;
    const domain_in_title = title.toLowerCase().includes(
        hostname.replace('www.', '').split('.')[0]
    ) ? 1 : 0;

    // Check copyright in page
    const bodyText = document.body ? document.body.innerText.toLowerCase() : '';
    const domain_with_copyright = (
        bodyText.includes('©') && 
        bodyText.includes(hostname.split('.')[0])
    ) ? 1 : 0;

    // Safe anchor ratio
    const safe_anchor = nullLinks / total;

    // Submit email
    const submit_email = bodyHTML.includes('mailto:') ? 1 : 0;

    // External CSS
    const cssLinks = document.querySelectorAll('link[rel="stylesheet"]');
    let nb_extCSS = 0;
    cssLinks.forEach(c => {
        if (c.href && !c.href.includes(hostname)) nb_extCSS++;
    });

    // SFH - suspicious form handler
    let sfh = 0;
    forms.forEach(form => {
        const action = form.getAttribute('action') || '';
        if (action === '' || action === '#' || action === 'about:blank' ||
            (action.startsWith('http') && !action.includes(hostname))) {
            sfh = 1;
        }
    });

    return {
        nb_hyperlinks,
        ratio_intHyperlinks: parseFloat((intLinks / total).toFixed(4)),
        ratio_extHyperlinks: parseFloat((extLinks / total).toFixed(4)),
        ratio_nullHyperlinks: parseFloat((nullLinks / total).toFixed(4)),
        iframe: iframes.length > 0 ? 1 : 0,
        login_form,
        external_favicon,
        links_in_tags,
        onmouseover,
        right_clic,
        popup_window,
        empty_title,
        domain_in_title,
        domain_with_copyright,
        safe_anchor: parseFloat(safe_anchor.toFixed(4)),
        submit_email,
        nb_extCSS,
        sfh
    };
}

// Listen for message from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "extractFeatures") {
        const features = extractDOMFeatures();
        sendResponse({ features });
    }
    return true;
});