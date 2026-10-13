// Interactivity for jekyll-tabs markup: tab switching, same-label sync, and
// site-wide persistence of the selected language across pages via localStorage.
(function () {
  'use strict';

  var STORAGE_KEY = 'antissrf-lang';

  function childIndex(el) {
    var i = 0;
    while ((el = el.previousElementSibling) !== null) {
      i++;
    }
    return i;
  }

  function activate(link) {
    var li = link.parentNode;
    var tabList = li.parentNode; // <ul class="tab" data-tab="...">
    var contentId = tabList.getAttribute('data-tab');
    var content = contentId ? document.getElementById(contentId) : null;
    if (!content) {
      return;
    }

    var index = childIndex(li);
    var i;
    for (i = 0; i < tabList.children.length; i++) {
      tabList.children[i].classList.remove('active');
    }
    for (i = 0; i < content.children.length; i++) {
      content.children[i].classList.remove('active');
    }

    li.classList.add('active');
    if (content.children[index]) {
      content.children[index].classList.add('active');
    }
  }

  function syncByLabel(link) {
    var label = link.textContent.trim();
    var links = document.querySelectorAll('ul.tab > li > a');
    for (var i = 0; i < links.length; i++) {
      if (links[i] !== link && links[i].textContent.trim() === label) {
        activate(links[i]);
      }
    }
  }

  function restore() {
    var saved;
    try {
      saved = localStorage.getItem(STORAGE_KEY);
    } catch (e) {
      return;
    }
    if (!saved) {
      return;
    }
    var links = document.querySelectorAll('ul.tab > li > a');
    for (var i = 0; i < links.length; i++) {
      if (links[i].textContent.trim() === saved) {
        activate(links[i]);
        syncByLabel(links[i]);
        break;
      }
    }
  }

  function init() {
    var links = document.querySelectorAll('ul.tab > li > a');
    Array.prototype.forEach.call(links, function (link) {
      link.addEventListener('click', function (e) {
        e.preventDefault();
        activate(link);
        syncByLabel(link);
        try {
          localStorage.setItem(STORAGE_KEY, link.textContent.trim());
        } catch (err) {
          /* ignore storage errors */
        }
      });
    });
    restore();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
