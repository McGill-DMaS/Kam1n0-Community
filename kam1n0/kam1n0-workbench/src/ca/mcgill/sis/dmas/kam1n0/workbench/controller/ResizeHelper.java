package ca.mcgill.sis.dmas.kam1n0.workbench.controller;

import javafx.collections.ObservableList;
import javafx.event.EventHandler;
import javafx.event.EventType;
import javafx.scene.Cursor;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.input.MouseEvent;
import javafx.stage.Stage;

// created by Alexander Berg
// modified by Steven (added padding)
// from https://stackoverflow.com/questions/19455059/allow-user-to-resize-an-undecorated-stage
public class ResizeHelper {

	public static boolean resizeDisabled = false;

	public static void addResizeListener(Stage stage, int padding, double minHeight, double minWidth) {
		ResizeListener resizeListener = new ResizeListener(stage, padding);
		resizeListener.minHeight = minHeight;
		resizeListener.minWidth = minWidth;
		stage.getScene().addEventHandler(MouseEvent.MOUSE_MOVED, resizeListener);
		stage.getScene().addEventHandler(MouseEvent.MOUSE_PRESSED, resizeListener);
		stage.getScene().addEventHandler(MouseEvent.MOUSE_DRAGGED, resizeListener);
		stage.getScene().addEventHandler(MouseEvent.MOUSE_EXITED, resizeListener);
		stage.getScene().addEventHandler(MouseEvent.MOUSE_EXITED_TARGET, resizeListener);
		ObservableList<Node> children = stage.getScene().getRoot().getChildrenUnmodifiable();
		for (Node child : children) {
			addListenerDeeply(child, resizeListener);
		}
	}

	public static void addListenerDeeply(Node node, EventHandler<MouseEvent> listener) {
		node.addEventHandler(MouseEvent.MOUSE_MOVED, listener);
		node.addEventHandler(MouseEvent.MOUSE_PRESSED, listener);
		node.addEventHandler(MouseEvent.MOUSE_DRAGGED, listener);
		node.addEventHandler(MouseEvent.MOUSE_EXITED, listener);
		node.addEventHandler(MouseEvent.MOUSE_EXITED_TARGET, listener);
		if (node instanceof Parent) {
			Parent parent = (Parent) node;
			ObservableList<Node> children = parent.getChildrenUnmodifiable();
			for (Node child : children) {
				addListenerDeeply(child, listener);
			}
		}
	}

	static class ResizeListener implements EventHandler<MouseEvent> {
		private Stage stage;
		private Cursor cursorEvent = Cursor.DEFAULT;
		private int border = 3;
		private double startX = 0;
		private double startY = 0;
		private int padding;

		public ResizeListener(Stage stage, int padding) {
			this.stage = stage;
			this.padding = padding;
		}

		// Max and min sizes for controlled stage
		public double minWidth = Double.MIN_VALUE;
		public double maxWidth = Double.MAX_VALUE;
		public double minHeight = Double.MIN_VALUE;
		public double maxHeight = Double.MAX_VALUE;

		@Override
		public void handle(MouseEvent mouseEvent) {

			EventType<? extends MouseEvent> mouseEventType = mouseEvent.getEventType();
			Scene scene = stage.getScene();

			double mouseEventX = mouseEvent.getSceneX(), mouseEventY = mouseEvent.getSceneY(),
					sceneWidth = scene.getWidth(), sceneHeight = scene.getHeight();

			if (MouseEvent.MOUSE_MOVED.equals(mouseEventType) == true) {
				if (resizeDisabled)
					return;
				if (mouseEventX < border + padding && mouseEventY < border + padding) {
					cursorEvent = Cursor.NW_RESIZE;
				} else if (mouseEventX < border + padding && mouseEventY > sceneHeight - border - padding) {
					cursorEvent = Cursor.SW_RESIZE;
				} else if (mouseEventX > sceneWidth - padding - border && mouseEventY < border + padding) {
					cursorEvent = Cursor.NE_RESIZE;
				} else if (mouseEventX > sceneWidth - padding - border
						&& mouseEventY > sceneHeight - border - padding) {
					cursorEvent = Cursor.SE_RESIZE;
				} else if (mouseEventX < border + padding) {
					cursorEvent = Cursor.W_RESIZE;
				} else if (mouseEventX > sceneWidth - padding - border) {
					cursorEvent = Cursor.E_RESIZE;
				} else if (mouseEventY < border + padding) {
					cursorEvent = Cursor.N_RESIZE;
				} else if (mouseEventY > sceneHeight - padding - border) {
					cursorEvent = Cursor.S_RESIZE;
				} else {
					cursorEvent = Cursor.DEFAULT;
				}
				scene.setCursor(cursorEvent);
			} else if (MouseEvent.MOUSE_EXITED.equals(mouseEventType)
					|| MouseEvent.MOUSE_EXITED_TARGET.equals(mouseEventType)) {
				scene.setCursor(Cursor.DEFAULT);
			} else if (MouseEvent.MOUSE_PRESSED.equals(mouseEventType) == true) {
				if (resizeDisabled)
					return;
				startX = stage.getWidth() - mouseEventX;
				startY = stage.getHeight() - mouseEventY;
			} else if (MouseEvent.MOUSE_DRAGGED.equals(mouseEventType) == true) {
				if (resizeDisabled)
					return;
				if (Cursor.DEFAULT.equals(cursorEvent) == false) {
					if (Cursor.W_RESIZE.equals(cursorEvent) == false && Cursor.E_RESIZE.equals(cursorEvent) == false) {
						double minHeight = stage.getMinHeight() > (border * 2) ? stage.getMinHeight() : (border * 2);
						if (Cursor.NW_RESIZE.equals(cursorEvent) == true || Cursor.N_RESIZE.equals(cursorEvent) == true
								|| Cursor.NE_RESIZE.equals(cursorEvent) == true) {
							if (stage.getHeight() > minHeight || mouseEventY < 0) {
								setStageHeight(stage.getY() - mouseEvent.getScreenY() + stage.getHeight() + padding);
								stage.setY(mouseEvent.getScreenY() - padding);
							}
						} else {
							if (stage.getHeight() > minHeight || mouseEventY + startY - stage.getHeight() > 0) {
								setStageHeight(mouseEventY + startY);
							}
						}
					}

					if (Cursor.N_RESIZE.equals(cursorEvent) == false && Cursor.S_RESIZE.equals(cursorEvent) == false) {
						double minWidth = stage.getMinWidth() > (border * 2) ? stage.getMinWidth() : (border * 2);
						if (Cursor.NW_RESIZE.equals(cursorEvent) == true || Cursor.W_RESIZE.equals(cursorEvent) == true
								|| Cursor.SW_RESIZE.equals(cursorEvent) == true) {
							if (stage.getWidth() > minWidth || mouseEventX < 0) {
								setStageWidth(stage.getX() - mouseEvent.getScreenX() + stage.getWidth() + padding);
								stage.setX(mouseEvent.getScreenX() - padding);
							}
						} else {
							if (stage.getWidth() > minWidth || mouseEventX + startX - stage.getWidth() > 0) {
								setStageWidth(mouseEventX + startX);
							}
						}
					}
				}
			}
		}

		private void setStageWidth(double width) {
			width = Math.min(width, maxWidth);
			width = Math.max(width, minWidth);
			stage.setWidth(width);
		}

		private void setStageHeight(double height) {
			height = Math.min(height, maxHeight);
			height = Math.max(height, minHeight);
			stage.setHeight(height);
		}
	}
}