document.addEventListener('DOMContentLoaded', function() {
    console.log('main.js is running');
    const contentArea = document.getElementById('content-area');
    const backButton = document.getElementById('back-button');
    const categoriesContainer = document.getElementById('categories-container');
    const categoryItems = document.querySelectorAll('.category-item');
    const siteBaseUrl = document.querySelector('base')?.href || window.location.origin + '/';
    //let previousUrl = null;

    console.log('Site Base URL:', siteBaseUrl);
    console.log('Number of category items:', categoryItems.length);
    console.log('Categories container HTML:', categoriesContainer.innerHTML);

    function showContent() {
        contentArea.style.transform = 'translateX(0)';
        contentArea.style.opacity = '1';
        contentArea.style.display = 'block';
    }

    function hideContent() {
        contentArea.style.transform = 'translateX(100%)';
        contentArea.style.opacity = '0';
    }

    function loadContent(url) {
        hideContent();
        fetch(url)
            .then(response => response.text())
            .then(html => {
                const parser = new DOMParser();
                const doc = parser.parseFromString(html, 'text/html');
                const newContent = doc.querySelector('#content-area');
    
                if (newContent) {
                    contentArea.innerHTML = newContent.innerHTML;
                    applyStyles();
                    backButton.style.display = 'inline-block';
                    setTimeout(() => {
                        showContent();
                        addAllLinkListeners();
                    }, 100);
                    // store current url as previous url
                    //previousUrl = url;
                } else {
                    throw new Error('Content not found in loaded page');
                }
            })
            .catch(error => {
                contentArea.innerHTML = `<p>Error loading content. Please try again.</p>`;
                backButton.style.display = 'inline-block';
                showContent();
            });
    }

    function applyStyles() {
        const markdownElements = contentArea.querySelectorAll('p, h1, h2, h3, h4, h5, h6, ul, ol, blockquote, pre, code');
        markdownElements.forEach(el => {
            el.classList.add('markdown-content');
        });

        // Style post lists
        const postLists = contentArea.querySelectorAll('ul');
        postLists.forEach(list => {
            list.classList.add('post-list');
            const listItems = list.querySelectorAll('li');
            listItems.forEach(item => {
                const link = item.querySelector('a');
                const date = item.querySelector('span');
                if (date) {
                    date.classList.add('post-date');
                    item.insertBefore(date, link);
                }
            });
        });
    }

    function addAllLinkListeners() {
        const links = contentArea.querySelectorAll('a');
        links.forEach(link => {
            if (link.hostname === window.location.hostname) {
                link.addEventListener('click', function(e) {
                    e.preventDefault();
                    const url = this.href;
                    loadContent(url);
                });
            }
        });
    }

    categoryItems.forEach(item => {
        item.addEventListener('click', function(e) {
            e.preventDefault();
            const url = this.href;
            
            console.log(`Loading category: ${url}`);

            if (!url) {
                console.error('URL is null or empty');
                return;
            }

            categoriesContainer.style.opacity = '0';
            hideContent();

            setTimeout(() => {
                categoriesContainer.style.display = 'none';
                loadContent(url);
            }, 250);
        });
    });

    backButton.addEventListener('click', function() {
        hideContent();
        backButton.style.display = 'none';
        
        setTimeout(() => {
            contentArea.innerHTML = '';
            contentArea.setAttribute('data-page-type', 'home');
            categoriesContainer.style.display = 'flex';
            categoriesContainer.style.opacity = '1';
            showContent();
        }, 250);
    });

    // Initial setup
    addAllLinkListeners();
});