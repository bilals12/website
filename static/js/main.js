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
            // Handle ordered lists specifically
            if (el.tagName === 'OL') {
                const items = el.querySelectorAll('li');
                items.forEach(item => {
                    // Preserve any existing content
                    const content = item.innerHTML;
                    item.innerHTML = content;
                });
            }
        });

        // Add specific handling for code blocks
        const codeBlocks = contentArea.querySelectorAll('pre, code');
        codeBlocks.forEach(block => {
            if (block.tagName === 'PRE') {
                block.style.backgroundColor = 'rgba(5, 10, 9, 0.5)';
            }
            const codeElements = block.querySelectorAll('code');
            codeElements.forEach(code => {
                code.style.fontFamily = '"Ubuntu Mono", monospace';
            });
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
                         urlPath.includes('/posts/') && !urlPath.endsWith('/posts/') ? 'post' :
                         urlPath.includes('/photography/') && !urlPath.endsWith('/photography/') ? 'photo' :
                         'other';

        // For about/cv/individual posts, update URL and load with proper styling
        if (pageType === 'about' || pageType === 'cv' || pageType === 'post' || pageType === 'photo') {
            // Update the URL without page reload
            window.history.pushState({}, '', urlPath);
            
            const absoluteUrl = new URL(urlPath, window.location.origin).href;
            fetch(absoluteUrl)
                .then(response => response.text())
                .then(html => {
                    const parser = new DOMParser();
                    const doc = parser.parseFromString(html, 'text/html');
                    const newContent = doc.querySelector('#content-area');
                    
                    if (newContent) {
                        // Preserve the original styling by keeping the structure
                        contentArea.innerHTML = newContent.innerHTML;
                        contentArea.style.transform = 'none';
                        contentArea.style.opacity = '1';
                        contentArea.setAttribute('data-page-type', pageType);
                        
                        // Apply the proper markdown styling
                        const markdownContent = contentArea.querySelector('.markdown-content');
                        if (markdownContent) {
                            markdownContent.style.textAlign = pageType === 'about' || pageType === 'cv' ? 'center' : 'left';
                        }
                        
                        backButton.style.display = 'inline-block';
                        addAllLinkListeners();
                        addBottomBackButton();
                        previousUrl = absoluteUrl;
                        isInCategoryList = false;
                    } else {
                        throw new Error('Content not found in loaded page');
                    }
                })
                .catch(error => {
                    contentArea.innerHTML = `<p>Error loading content. Please try again.</p>`;
                    backButton.style.display = 'inline-block';
                });
            return;
        }

        // For category list pages (posts/ and photography/), keep the existing sliding animation
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
        const pageType = contentArea.getAttribute('data-page-type');
        if (pageType === 'about' || pageType === 'cv') {
            goToHomePage();
        } else if (pageType === 'post') {
            loadContent('/posts/');
        } else if (pageType === 'photo') {
            loadContent('/photography/');
        } else if (isInCategoryList) {
            goToHomePage();
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
            
            // For about/cv, hide categories immediately without animation
            if (url.includes('/about/') || url.includes('/cv/')) {
                categoriesContainer.style.display = 'none';
                loadContent(url);
                return;
            }

            // For other categories, keep existing animation
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
        if (contentArea.getAttribute('data-page-type') === 'about' || 
            contentArea.getAttribute('data-page-type') === 'cv') {
            // For about/cv pages, animate the transition back
            hideContent();
            backButton.style.display = 'none';
            setTimeout(() => {
                contentArea.innerHTML = '';
                contentArea.setAttribute('data-page-type', 'home');
                categoriesContainer.style.display = 'flex';
                setTimeout(() => {
                    categoriesContainer.style.opacity = '1';
                }, 50);
            }, 300);
        } else {
            // Original behavior for other pages
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
    }

    const pageType = contentArea.getAttribute('data-page-type');
    if (pageType === 'single' || pageType === 'cv') {
        addBottomBackButton();
    }
});
