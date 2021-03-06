package org.zywx.wbpalmstar.engine.webview;

import org.xwalk.core.XWalkJavascriptResult;
import org.xwalk.core.XWalkUIClient;
import org.xwalk.core.XWalkView;
import org.zywx.wbpalmstar.base.BDebug;
import org.zywx.wbpalmstar.engine.EBrowserActivity;
import org.zywx.wbpalmstar.engine.EBrowserView;
import org.zywx.wbpalmstar.engine.EBrowserWindow;
import org.zywx.wbpalmstar.engine.ESystemInfo;
import org.zywx.wbpalmstar.engine.universalex.EUExScript;

import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.DialogInterface.OnClickListener;
import android.content.Intent;
import android.graphics.Bitmap;
import android.net.Uri;
import android.os.Build;
import android.os.Message;
import android.view.KeyEvent;
import android.webkit.CookieSyncManager;
import android.webkit.ValueCallback;
import android.widget.EditText;

public class CBrowserMainFrame extends XWalkUIClient {
	protected String mParms;
	protected String mReferenceUrl;

	public CBrowserMainFrame(XWalkView view) {
		super(view);
		mReferenceUrl="";
	}

	@Override
	public boolean onConsoleMessage(XWalkView view, String message,
			int lineNumber, String sourceId, ConsoleMessageType messageType) {
		return super.onConsoleMessage(view, message, lineNumber, sourceId,
				messageType);
	}

	@Override
	public boolean onCreateWindowRequested(XWalkView view,
			InitiateBy initiator, ValueCallback<XWalkView> callback) {
		return super.onCreateWindowRequested(view, initiator, callback);
	}

	@Override
	public void onFullscreenToggled(XWalkView view, boolean enterFullscreen) {
		super.onFullscreenToggled(view, enterFullscreen);
	}

	@Override
	public void onIconAvailable(XWalkView view, String url,
			Message startDownload) {
		super.onIconAvailable(view, url, startDownload);
	}

	@Override
	public void onJavascriptCloseWindow(XWalkView view) {
		super.onJavascriptCloseWindow(view);
	}

	@Override
	public boolean onJavascriptModalDialog(XWalkView view,
			JavascriptMessageType type, String url, String message,
			String defaultValue, final XWalkJavascriptResult result) {
		if (!((EBrowserActivity) view.getContext()).isVisable()) {
			result.confirm();
		}
		AlertDialog.Builder dia = new AlertDialog.Builder(view.getContext());
		dia.setTitle("提示消息");
		dia.setMessage(message);
		dia.setPositiveButton("确定", new OnClickListener() {
			public void onClick(DialogInterface dialog, int which) {
				result.confirm();
			}
		});
		if (type != JavascriptMessageType.JAVASCRIPT_ALERT) {
			dia.setNegativeButton("取消", new DialogInterface.OnClickListener() {
				public void onClick(DialogInterface dialog, int which) {
					result.cancel();
				}
			});
		}
		if (type == JavascriptMessageType.JAVASCRIPT_PROMPT) {
			final EditText input = new EditText(view.getContext());
			if (defaultValue != null) {
				input.setText(defaultValue);
			}
			input.setSelectAllOnFocus(true);
			dia.setView(input);
		}
		dia.create();
		dia.show();
		return true;
	}

	@Override
	public void onPageLoadStarted(XWalkView view, String url) {
		BDebug.i("url ",url);
		if (view == null) {
			return;
		}
		EBrowserView target = (EBrowserView) view;
		target.onPageStarted(target, url);
		if (null != mParms) {
			target.setQuery(mParms);
		}
		mParms = null;
		ESystemInfo info = ESystemInfo.getIntence();
		if (info.mFinished) {
			info.mScaled = true;
		}
		if (url != null) {
			mReferenceUrl = url;
			if (url.startsWith("http")) {
				EBrowserWindow bWindow = target.getBrowserWindow();
				if (bWindow != null && 1 == bWindow.getWidget().m_webapp) {
					bWindow.showProgress();
				}
			}
		}
	}

	@Override
	public void onPageLoadStopped(XWalkView view, String url, LoadStatus status) {
		BDebug.i("url ",url, status);
		if (status == LoadStatus.FINISHED) {
			if (view == null) {
				return;
			}
			EBrowserView target = (EBrowserView) view;
			EBrowserWindow bWindow = target.getBrowserWindow();
			if (url != null) {
				if (url.startsWith("http")) {
					if (bWindow != null && 1 == bWindow.getWidget().m_webapp) {
						bWindow.hiddenProgress();
					}
				}
				String oUrl = view.getOriginalUrl();
				if (!mReferenceUrl.equals(url) || target.beDestroy()
						|| !url.equals(oUrl)) {
					return;
				}
			}
			ESystemInfo info = ESystemInfo.getIntence();

			int versionA = Build.VERSION.SDK_INT;

			if (!target.isWebApp()) { // 4.3及4.3以下手机
				if (!info.mScaled) {
					float nowScale = 1.0f;

					if (versionA <= 18) {
						nowScale = target.getScale();
					}

					info.mDefaultFontSize = (int) (info.mDefaultFontSize / nowScale);
					info.mScaled = true;

				}

				target.setDefaultFontSize(info.mDefaultFontSize);
			}

			if (!info.mFinished) {
				((EBrowserActivity) target.getContext())
						.setContentViewVisible();
			}

			info.mFinished = true;
			target.loadUrl(EUExScript.F_UEX_SCRIPT);
			target.onPageFinished(target, url);
			if (bWindow != null && bWindow.getWidget().m_appdebug == 1) {
				String debugUrlString = "http://"
						+ bWindow.getWidget().m_logServerIp
						+ ":30060/target/target-script-min.js#anonymous";
				String weinreString = "javascript:var x = document.createElement(\"SCRIPT\");x.setAttribute('src',\""
						+ debugUrlString
						+ "\""
						+ ");document.body.appendChild(x);";
				target.loadUrl(weinreString);
			}

			CookieSyncManager.getInstance().sync();

			BDebug.i(url, "   loaded");
		}

	}

	@Override
	public void onReceivedIcon(XWalkView view, String url, Bitmap icon) {
		super.onReceivedIcon(view, url, icon);
	}

	@Override
	public void onReceivedTitle(XWalkView view, String title) {
		super.onReceivedTitle(view, title);
	}

	@Override
	public void onRequestFocus(XWalkView view) {
		super.onRequestFocus(view);
	}

	@Override
	public void onScaleChanged(XWalkView view, float oldScale, float newScale) {
		super.onScaleChanged(view, oldScale, newScale);
	}

	@Override
	public void onUnhandledKeyEvent(XWalkView view, KeyEvent event) {
		super.onUnhandledKeyEvent(view, event);
	}

	@Override
	public void openFileChooser(XWalkView view, ValueCallback<Uri> uploadFile,
			String acceptType, String capture) {
		((EBrowserActivity) view.getContext()).setmUploadMessage(uploadFile);
		Intent i = new Intent(Intent.ACTION_GET_CONTENT);
		i.addCategory(Intent.CATEGORY_OPENABLE);
		i.setType("*/*");
		((EBrowserActivity) view.getContext()).startActivityForResult(
				Intent.createChooser(i, "File Chooser"),
				EBrowserActivity.FILECHOOSER_RESULTCODE);
	}

	@Override
	public boolean shouldOverrideKeyEvent(XWalkView view, KeyEvent event) {
		// TODO Auto-generated method stub
		return super.shouldOverrideKeyEvent(view, event);
	}
}
