(() => {
    'use strict';
    const form = document.getElementById('ls-settings-form');
    if (!form) return;
    const sections = [...form.querySelectorAll('.ls-section')];
    const status = document.getElementById('ls-save-status');
    const signature = () => new URLSearchParams(new FormData(form)).toString();
    const initial = signature();
    let dirty = false;
    let submitting = false;
    // 只折叠展示，不禁用或移除字段，确保所有组完整提交。
    const openSection = (section) => {
        sections.forEach(item => { item.open = item === section; });
    };
    sections.forEach(section => {
        section.querySelector('summary').addEventListener('click', event => {
            if (!section.open) {
                event.preventDefault();
                openSection(section);
            }
        });
    });
    const changed = () => {
        dirty = signature() !== initial;
        form.classList.toggle('is-dirty', dirty);
        status.textContent = dirty ? '有未保存的更改' : '所有分组统一保存';
    };
    form.addEventListener('input', changed);
    form.addEventListener('change', changed);
    form.addEventListener('invalid', event => {
        // 浏览器校验发生在提交之前，先展开出错字段所在组才能正常聚焦。
        const section = event.target.closest('.ls-section');
        if (section) section.open = true;
        for (let parent = event.target.parentElement; parent && parent !== form; parent = parent.parentElement) {
            if (parent.tagName === 'DETAILS') parent.open = true;
        }
    }, true);
    form.addEventListener('submit', () => {
        submitting = true;
        status.textContent = '正在保存…';
        // 不禁用提交按钮或设置字段，保留原生表单语义。
    });
    window.addEventListener('beforeunload', event => {
        if (dirty && !submitting) { event.preventDefault(); event.returnValue = ''; }
    });
})();
