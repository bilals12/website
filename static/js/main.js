document.addEventListener('DOMContentLoaded', function() {
    const contentArea = document.getElementById('content-area');
    const backButton = document.getElementById('back-button');
    const categoriesContainer = document.getElementById('categories-container');
    const categoryItems = document.querySelectorAll('.category-item');
    const siteBaseUrl = document.querySelector('base')?.href || window.location.origin + '/';

    // flag to prevent multiple animations starting simultaneously
    let isAnimating = false;

    // CSS transitions instead of requestAnimationFrame for smoother animations
    // timings adjusted to make sure animations complete before new content is loaded
    // determining transition speeds based on page type (quicker for about + cv)
    function showContent(pageType) {
        isAnimating = true;
        const duration = (pageType === 'about' || pageType === 'cv') ? '0.1s' : '0.2s';
        const easing = 'cubic-bezier(0.25, 0.1, 0.25, 1.0)'; // smoother easing function
        contentArea.style.transition = `transform ${duration} ${easing}, opacity ${duration} ${easing}`;
        contentArea.style.transform = 'translateX(0)';
        contentArea.style.opacity = '1';
        contentArea.style.display = 'block';
        setTimeout(() => {
            isAnimating = false;
        }, (pageType === 'about' || pageType === 'cv') ? 100 : 200);
    }

    function hideContent(pageType) {
        if (isAnimating) return;
        isAnimating = true;
        const duration = (pageType === 'about' || pageType === 'cv') ? '0.1s' : '0.2s';
        const easing = 'cubic-bezier(0.25, 0.1, 0.25, 1.0)'; // smoother easing function
        contentArea.style.transition = `transform ${duration} ${easing}, opacity ${duration} ${easing}`;
        contentArea.style.transform = 'translateX(100%)';
        contentArea.style.opacity = '0';
        setTimeout(() => {
            isAnimating = false;
        }, (pageType === 'about' || pageType === 'cv') ? 100 : 200);
    }

    function applyStyles() {
        const markdownElements = contentArea.querySelectorAll('p, h1, h2, h3, h4, h5, h6, ul, ol, blockquote, pre, code');
        markdownElements.forEach(el => {
            el.classList.add('markdown-content');
        });

        // style post lists
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

    function loadContent(url) {
        if (isAnimating) return;
        const urlPath = new URL(url, window.location.origin).pathname;
        const pageType = urlPath.includes('/about/') ? 'about' : 
                         urlPath.includes('/cv/') ? 'cv' : 
                         'other';
        hideContent(pageType);
        const absoluteUrl = new URL(urlPath, window.location.origin).href;

        fetch(absoluteUrl)
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                return response.text();
            })
            .then(html => {
                const parser = new DOMParser();
                const doc = parser.parseFromString(html, 'text/html');
                const newContent = doc.querySelector('#content-area');
    
                if (newContent) {
                    setTimeout(() => {
                        contentArea.innerHTML = newContent.innerHTML;
                        contentArea.setAttribute('data-page-type', pageType === 'other' ? 'single' : pageType);
                        contentArea.style.background = 'rgba(41, 82, 74, 0.2)';
                        contentArea.style.backdropFilter = 'blur(5px)';
                        contentArea.style.webkitBackdropFilter = 'blur(5px)';
                        applyStyles();
                        backButton.style.display = 'inline-block';
                        showContent(pageType);
                        addAllLinkListeners();
                        addBottomBackButton();
                    }, (pageType === 'about' || pageType === 'cv') ? 200 : 300);
                    previousUrl = absoluteUrl;
                    isInCategoryList = urlPath.endsWith('/posts/') || urlPath.endsWith('/photography/');
                } else {
                    throw new Error('Content not found in loaded page');
                }
            })
            .catch(error => {
                contentArea.innerHTML = `<p>Error loading content. Please try again.</p>`;
                backButton.style.display = 'inline-block';
                showContent(pageType);
            });
    }

    function addBottomBackButton() {
        const existingButton = contentArea.querySelector('#bottom-back-button');
        if (!existingButton) {
            const bottomBackButton = document.createElement('button');
            bottomBackButton.id = 'bottom-back-button';
            bottomBackButton.innerHTML = backButton.innerHTML;;
            bottomBackButton.addEventListener('click', handleBackButtonClick);
            contentArea.appendChild(bottomBackButton);
        }
    }

    function handleBackButtonClick() {
        if (isInCategoryList) {
            goToHomePage();
        } else if (previousUrl) {
            if (previousUrl.includes('/posts/')) {
                loadContent('/posts/');
            } else if (previousUrl.includes('/photography/')) {
                loadContent('/photography/');
            } else {
                goToHomePage();
            }
        } else {
            goToHomePage();
        }
    }

    function initializePageState() {
        const pageType = contentArea.getAttribute('data-page-type');
        if (pageType === 'single' || pageType === 'cv') {
            addBottomBackButton();
            if (backButton) {
                backButton.style.display = 'inline-block';
            }
            addAllLinkListeners();
            applyStyles();
        } else if (pageType === 'home') {
            if (categoriesContainer) {
                categoriesContainer.style.display = 'flex';
                categoriesContainer.style.opacity = '1';
            }
        }
        showContent(pageType);
    }

    initializePageState();

    categoryItems.forEach(item => {
        item.addEventListener('click', function(e) {
            e.preventDefault();
            if (isAnimating) return;
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
            }, 300);
        });
    });

    backButton.addEventListener('click', function() {
        if (isInCategoryList) {
            goToHomePage();
        } else if (previousUrl) {
            if (previousUrl.includes('/posts/')) {
                loadContent('/posts/');
            } else if (previousUrl.includes('/photography/')) {
                loadContent('/photography/');
            } else {
                goToHomePage();
            }
        } else {
            goToHomePage();
        }
    });

    function goToHomePage() {
        hideContent();
        backButton.style.display = 'none';
        setTimeout(() => {
            contentArea.innerHTML = '';
            contentArea.setAttribute('data-page-type', 'home');
            categoriesContainer.style.display = 'flex';
            categoriesContainer.style.opacity = '1';
            showContent();
        }, 100);
    }

    const pageType = contentArea.getAttribute('data-page-type');
    if (pageType === 'single' || pageType === 'cv') {
        addBottomBackButton();
    }
});