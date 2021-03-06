/*
 * Copyright (c) 2015.  The AppCan Open Source Project.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 */
package org.zywx.wbpalmstar.engine.webview;

import android.annotation.SuppressLint;
import android.content.Context;
import android.graphics.Color;
import android.os.Build;
import android.webkit.CookieSyncManager;
import android.webkit.WebResourceResponse;

import java.lang.reflect.Method;
import java.util.Map;

import org.xwalk.core.XWalkDownloadListener;
import org.xwalk.core.XWalkNavigationHistory;
import org.xwalk.core.XWalkPreferences;
import org.xwalk.core.XWalkResourceClient;
import org.xwalk.core.XWalkUIClient;
import org.xwalk.core.XWalkView;
import org.zywx.wbpalmstar.acedes.EXWebViewClient;
import org.zywx.wbpalmstar.base.BDebug;
import org.zywx.wbpalmstar.engine.EBrowserBaseSetting;
import org.zywx.wbpalmstar.engine.EBrowserView;
import org.zywx.wbpalmstar.engine.ESystemInfo;
import org.zywx.wbpalmstar.engine.universalex.EUExScript;
import org.zywx.wbpalmstar.engine.webview.EUExDispatcher;

/**
 * Created by ylt on 15/8/24.
 */
public class ACEWebView extends XWalkView {

	// use for debug
	protected Method mDumpDisplayTree;
	protected Method mDumpDomTree;
	protected Method mDumpRenderTree;
	protected Method mDrawPage;

	protected Method mDismissZoomControl;

	private EBrowserBaseSetting mBaSetting;
	private EXWebViewClient mEXWebViewClient;

	private CBrowserWindow mCBrowserWindow;
	
	public ACEWebView(Context context) {
		super(context);
	}

	static{
		XWalkPreferences.setValue(XWalkPreferences.ALLOW_UNIVERSAL_ACCESS_FROM_FILE, true);
		XWalkPreferences.setValue(XWalkPreferences.REMOTE_DEBUGGING, BDebug.DEBUG);
		XWalkPreferences.setValue(XWalkPreferences.SUPPORT_MULTIPLE_WINDOWS, true);
		XWalkPreferences.setValue(XWalkPreferences.JAVASCRIPT_CAN_OPEN_WINDOW, true);
//		XWalkPreferences.setValue(XWalkPreferences.ANIMATABLE_XWALK_VIEW, true);
	}
	
	protected void init(boolean webApp) {
		setBackgroundColor(0);
		setInitialScale(100);
		setAlpha(0.99f);
		setDrawingCacheBackgroundColor(Color.TRANSPARENT);
		setScrollbarFadingEnabled(false);
		setFadingEdgeLength(0);
		setWebViewClient();
		setWebChromeClient();
		zoomBy(1);
		setDownloadListener(new XWalkDownloadListener(getContext()) {

			@Override
			public void onDownloadStart(String arg0, String arg1, String arg2,
					String arg3, long arg4) {
				mCBrowserWindow.onDownloadStart(getContext(), arg0, arg1, arg2, arg3, arg4);
			}
			
		});
		if (webApp) {
			return;
		}
	}

	@SuppressLint("NewApi")
	public void pauseCore() {
		
	}

	public void resumeCore() {
		
	}

	public void initPrivateVoid() {

	}

	public void setDefaultFontSize(int size) {

	}

	public void setSupportZoom() {

	}

	public void onDownloadStart(String url, String userAgent,
			String contentDisposition, String mimetype, long contentLength) {

	}

	/**
	 * XWalkView 用load()方法load 比较长的js会有问题
	 * @param url
	 */
	public void loadUrl(String url) {
		if (url != null && url.startsWith("javascript:")) {
			super.evaluateJavascript(url, null);
		} else {
			super.load(url, null);
		}
	}

	public void loadUrl(String url, Map<String, String> extraHeaders) {
		loadUrl(url);
	}

	@Override
	public void addJavascriptInterface(Object object, String name) {
		super.addJavascriptInterface(object, name);
	}

	public void onPause() {
		pauseCore();
	}

	public void onResume() {
		resumeCore();
	}

	public void goForward() {
		getNavigationHistory().navigate(
				XWalkNavigationHistory.Direction.FORWARD, 1);
	}

	public void clearHistory() {
		if (getNavigationHistory()!=null) {
			getNavigationHistory().clear();
		}
	}

	public void clearView() {
		super.removeAllViews();
	}

	public void clearMatches() {

	}

	public float getScale() {
		return super.getScaleX();
	}

	public int getContentHeight() {
		return super.getMeasuredHeight();
	}

	public void setWebViewClient() {
		mCBrowserWindow=new CBrowserWindow(this);
//		setResourceClient(mCBrowserWindow);
	}

	public void setWebChromeClient() {
		setUIClient(new CBrowserMainFrame(this));
	}

	public void setInitialScale(int scale) {
		super.setScaleX(scale / 100.00f);
		super.setScaleY(scale / 100.00f);
		
	}

	public void setDownloadListener() {
		
	}

	public void destroy() {
		super.onDestroy();
	}

	public void removeJavascriptInterface(String uexName) {

	}

	public void loadData(String data, String mimeType, String encoding) {
		super.load(null, data);
	}

	public void loadDataWithBaseURL(String baseUrl, String data,
			String mimeType, String encoding, String failUrl) {
		super.load(baseUrl, data);
	}

	public void goBack() {
		getNavigationHistory().navigate(
				XWalkNavigationHistory.Direction.BACKWARD, 1);
	}

	public void setVerticalScrollbarOverlay(boolean flag) {
		
	}

	public void setHorizontalScrollbarOverlay(boolean flag) {

	}

	public void reload() {
		super.reload(0);
	}

	public boolean canGoBack() {
		return getNavigationHistory().canGoBack();
	}

	public boolean canGoForward() {
		return getNavigationHistory().canGoForward();
	}

	public boolean isHardwareAccelerated() {
		return true;
	}

}