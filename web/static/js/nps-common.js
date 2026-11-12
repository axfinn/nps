/*
 * nps-common.js —— nps 管理面板前端公共脚本
 *
 * 设计原则（不影响任何既有功能）：
 *  - 使用独立命名空间 window.NPS，避免与 layout.html 末尾
 *    `window.nps = {web_base_url}` 的简单赋值冲突（后者会整体覆盖 window.nps），
 *    也避免与页面元素 id（如 #table）重名导致全局函数被 DOM 遮蔽。
 *  - 仅封装被多个列表页重复书写、且行为完全一致的基础配置；
 *    调用方通过 opts 传入差异项（url / queryParams / columns / detailFormatter 等）。
 *  - 所有公共配置项都逐项与各 list 页面原有的显式设置核对一致；
 *    “并非所有页面共有”的项（detailView、showColumns、pageList、onExpandRow、
 *    onPostBody、onLoadSuccess 等）不放入 BASE_TABLE，由调用方按需声明，确保完全等价。
 */
window.NPS = window.NPS || {};
(function (NPS) {
    'use strict';

    // 所有列表页共用的基础配置（逐项核对一致：method/post、contentType、
    // striped/true、search/true、showRefresh/true、pagination/true、
    // sidePagination/server、pageNumber/1、showHeader/true、smartDisplay/true）。
    var BASE_TABLE = {
        toolbar: '#toolbar',
        method: 'post',
        contentType: 'application/x-www-form-urlencoded',
        striped: true,
        search: true,
        showRefresh: true,
        pagination: true,
        sidePagination: 'server',
        pageNumber: 1,
        showHeader: true,
        smartDisplay: true
    };

    // 展开详情行后刷新多语言标签
    function onExpandRowLang() {
        $('body').setLang('.detail-view');
    }
    // 数据渲染完成后刷新多语言标签（仅在表格已设置 locale 时）
    function onPostBodyLang() {
        if ($(this)[0].locale != undefined) {
            $('body').setLang('#table');
        }
    }

    // 通用表格：合并 BASE_TABLE 与调用方传入的差异项（浅合并，数组/函数整体替换）。
    NPS.table = function (selector, opts) {
        var cfg = $.extend({}, BASE_TABLE, opts || {});
        $(selector).bootstrapTable(cfg);
        return cfg;
    };

    // 带详情行（detailView）的表格：在通用基础配置之上补充详情相关配置。
    // client / 隧道 / host 列表页共用；调用方仍可覆盖其中任意项。
    NPS.detailTable = function (selector, opts) {
        var extra = {
            detailView: true,
            showColumns: true,
            onExpandRow: onExpandRowLang,
            onPostBody: onPostBodyLang
        };
        var cfg = $.extend({}, BASE_TABLE, extra, opts || {});
        $(selector).bootstrapTable(cfg);
        return cfg;
    };

    // 状态徽章：开 / 关（langtag 由 setLang 渲染为当前语言）
    NPS.badgeOpenClose = function (value) {
        return value
            ? '<span class="badge badge-primary" langtag="word-open"></span>'
            : '<span class="badge badge-badge" langtag="word-close"></span>';
    };

    // 状态徽章：在线 / 离线
    NPS.badgeOnlineOffline = function (value) {
        return value
            ? '<span class="badge badge-primary" langtag="word-online"></span>'
            : '<span class="badge badge-badge" langtag="word-offline"></span>';
    };
})(window.NPS);
