/*******************************************************************************
 * Copyright 2017 McGill University All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package ca.mcgill.sis.dmas.kam1n0.workbench.controller;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.function.Consumer;

import ca.mcgill.sis.dmas.kam1n0.workbench.connector.Kam1n0Connector.PropertyBounding;
import de.jensd.fx.glyphs.materialdesignicons.MaterialDesignIcon;
import de.jensd.fx.glyphs.materialdesignicons.MaterialDesignIconView;
import javafx.beans.Observable;
import javafx.beans.binding.Bindings;
import javafx.beans.property.BooleanProperty;
import javafx.beans.property.SimpleBooleanProperty;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.geometry.Insets;
import javafx.scene.Cursor;
import javafx.scene.Parent;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.ContextMenu;
import javafx.scene.control.DialogPane;
import javafx.scene.control.MenuItem;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableColumn.CellEditEvent;
import javafx.scene.control.TableRow;
import javafx.scene.control.TableView;
import javafx.scene.control.TextField;
import javafx.scene.control.cell.TextFieldTableCell;
import javafx.scene.effect.ColorAdjust;
import javafx.scene.effect.DropShadow;
import javafx.scene.effect.Effect;
import javafx.scene.effect.GaussianBlur;
import javafx.scene.image.Image;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.AnchorPane;
import javafx.scene.paint.Color;
import javafx.scene.shape.Rectangle;
import javafx.scene.control.Alert.AlertType;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import javafx.stage.FileChooser.ExtensionFilter;
import javafx.stage.Stage;
import javafx.stage.StageStyle;
import javafx.scene.control.Label;
import javafx.scene.Node;
import javafx.scene.image.ImageView;

public class MainWindowController {

	private MainApp app;
	private BooleanProperty hasUncommitedChanges = new SimpleBooleanProperty(false);

	@FXML
	private void initialize() {

		propertyColumn.setCellValueFactory(cellData -> cellData.getValue().key);
		propertyColumn.setCellFactory(TextFieldTableCell.forTableColumn());
		propertyColumn.setOnEditStart(t -> hasUncommitedChanges.set(true));
		propertyColumn.setOnEditCancel(t -> hasUncommitedChanges.set(false));
		propertyColumn.setOnEditCommit(new EventHandler<CellEditEvent<PropertyBounding, String>>() {
			@Override
			public void handle(CellEditEvent<PropertyBounding, String> t) {
				String old = t.getRowValue().key.get();
				t.getRowValue().key.set(t.getNewValue());
				hasUncommitedChanges.set(false);
				boolean success = handleSave();
				if (!success)
					t.getRowValue().key.set(old);
			}
		});

		valueColumn.setCellValueFactory(cellData -> cellData.getValue().value);
		valueColumn.setCellFactory(TextFieldTableCell.forTableColumn());
		valueColumn.setOnEditStart(t -> hasUncommitedChanges.set(true));
		valueColumn.setOnEditCancel(t -> hasUncommitedChanges.set(false));
		valueColumn.setOnEditCommit(new EventHandler<CellEditEvent<PropertyBounding, String>>() {
			@Override
			public void handle(CellEditEvent<PropertyBounding, String> t) {
				String old = t.getRowValue().value.get();
				t.getRowValue().value.set(t.getNewValue());
				hasUncommitedChanges.set(false);
				boolean success = handleSave();
				if (!success)
					t.getRowValue().value.set(old);
			}
		});

		propertyTable.setRowFactory(tv -> {
			TableRow<PropertyBounding> row = new TableRow<>();
			final ContextMenu contextMenu = new ContextMenu();
			final MenuItem browseFileMenuItem = new MenuItem("Select a file as value");
			browseFileMenuItem.setOnAction(env -> {
				FileChooser chooser = new FileChooser();
				chooser.setTitle("Select a file");
				File file = chooser.showOpenDialog(app.stage);
				if (file != null) {
					String old = row.getItem().value.get();
					row.getItem().value.set(normalizePath(file.getAbsolutePath()));
					boolean success = handleSave();
					if (!success)
						row.getItem().value.set(old);
				}
			});
			browseFileMenuItem.disableProperty().bind(row.emptyProperty());
			final MenuItem browseDirMenuItem = new MenuItem("Select a directory as value");
			browseDirMenuItem.setOnAction(env -> {
				DirectoryChooser chooser = new DirectoryChooser();
				chooser.setTitle("Select a directory");
				File file = chooser.showDialog(app.stage);
				if (file != null) {
					String old = row.getItem().value.get();
					row.getItem().value.set(normalizePath(file.getAbsolutePath() + File.separator));
					boolean success = handleSave();
					if (!success)
						row.getItem().value.set(old);
				}
			});
			browseDirMenuItem.disableProperty().bind(row.emptyProperty());
			final MenuItem removeMenuItem = new MenuItem("Remove current property");
			removeMenuItem.setOnAction(ev -> propertyTable.getItems().remove(row.getItem()));
			removeMenuItem.disableProperty().bind(row.emptyProperty());
			final MenuItem newMenuItem = new MenuItem("Add new property");
			newMenuItem.setOnAction(ev -> handleAdd(ev));
			contextMenu.getItems().add(browseFileMenuItem);
			contextMenu.getItems().add(browseDirMenuItem);
			contextMenu.getItems().add(removeMenuItem);
			contextMenu.getItems().add(newMenuItem);
			row.contextMenuProperty()
					.bind(Bindings.when(enableTableViewMenu).then(contextMenu).otherwise((ContextMenu) null));
			return row;
		});
		stopButton.setDisable(true);
	}

	private double xOffset = 0;
	private double yOffset = 0;
	private BooleanProperty enableTableViewMenu = new SimpleBooleanProperty(false);

	public void setApp(MainApp app, int padding) {
		String v = getClass().getPackage().getImplementationVersion();
		v = v == null ? "IDE-Developing" : v;
		winTitle.setText("Kam1n0 v" + v);

		// Add observable list data to the table
		Insets initial_padding = new Insets(padding);
		rootPane.setPadding(initial_padding);
		rootPane.setEffect(new DropShadow(padding, Color.BLACK));

		windowBar.setOnMousePressed(new EventHandler<MouseEvent>() {
			@Override
			public void handle(MouseEvent event) {
				ResizeHelper.resizeDisabled = true;
				xOffset = event.getSceneX();
				yOffset = event.getSceneY();
			}
		});
		windowBar.setOnMouseDragged(new EventHandler<MouseEvent>() {
			@Override
			public void handle(MouseEvent event) {
				app.stage.setX(event.getScreenX() - xOffset);
				app.stage.setY(event.getScreenY() - yOffset);
			}
		});
		windowBar.setOnMouseReleased(new EventHandler<MouseEvent>() {
			@Override
			public void handle(MouseEvent event) {
				ResizeHelper.resizeDisabled = false;
			}
		});

		this.app = app;
		aboutBtn.setOnMouseClicked(ev -> this.handleAbout());
		closeBtn.setOnMouseClicked(ev -> {
			tabPane.getSelectionModel().select(0);
			app.logger.info("Cleaning up resource.......");
			app.close();
		});
		minimizeBtn.setOnMouseClicked(ev -> app.stage.setIconified(true));
		maximizeBtn.setOnMouseClicked(ev -> {
			if (app.stage.isMaximized()) {
				app.stage.setMaximized(false);
				rootPane.setPadding(initial_padding);
				ResizeHelper.resizeDisabled = false;
			} else {
				app.stage.setMaximized(true);
				rootPane.setPadding(new Insets(0));
				ResizeHelper.resizeDisabled = true;
			}
		});
		propertyTable.setItems(app.connector.getKamPropertyBoundings(app.connector.KAM1N0_PROPERTIES_DEFAULT));
		propertyTable.addEventHandler(MouseEvent.MOUSE_MOVED, event -> app.stage.getScene().setCursor(Cursor.DEFAULT));

		browseBtn.setOnMouseClicked(ev -> {
			FileChooser chooser = new FileChooser();
			chooser.setTitle("Select a property file");
			File file = chooser.showOpenDialog(app.stage);
			if (file != null) {
				enableTableViewMenu.set(false);
				propertyFile.setText(file.getAbsolutePath());
				propertyTable.setItems(app.connector.getKamPropertyBoundings(propertyFile.getText().trim()));
				enableTableViewMenu.set(true);
			} else {
			}
		});

		propertyFile.setText(app.connector.KAM1N0_PROPERTIES_DEFAULT);
		enableTableViewMenu.set(true);
	}

	@FXML
	AnchorPane rootPane;
	@FXML
	AnchorPane windowBar;
	@FXML
	AnchorPane maskPane;
	@FXML
	Label winTitle;

	@FXML
	TextField propertyFile;
	@FXML
	MaterialDesignIconView browseBtn;

	@FXML
	Button startButton;
	@FXML
	Button stopButton;
	@FXML
	MaterialDesignIconView aboutBtn;
	@FXML
	MaterialDesignIconView closeBtn;
	@FXML
	MaterialDesignIconView maximizeBtn;
	@FXML
	MaterialDesignIconView minimizeBtn;

	@FXML
	TabPane tabPane;

	@FXML
	private TableView<PropertyBounding> propertyTable;

	@FXML
	private TableColumn<PropertyBounding, String> propertyColumn;

	@FXML
	private TableColumn<PropertyBounding, String> valueColumn;

	private void setDisableAll(boolean value) {
		startButton.setDisable(value);
		stopButton.setDisable(value);
		propertyTable.setDisable(value);
	}

	@FXML
	public void handleStart(ActionEvent event) {

		if (hasUncommitedChanges.get()) {
			message(AlertType.ERROR, "Uncommited Changes.",
					"You have uncommited changes in table view. Please cancel or press enter in the editing cell to continue. ");
			return;
		}

		setDisableAll(true);
		stopButton.setDisable(false);
		app.connector.startEngine(propertyFile.getText().trim());
		tabPane.getSelectionModel().select(1);
	}

	@FXML
	public void handleStop(ActionEvent event) {
		tabPane.getSelectionModel().select(0);
		app.logger.info("Cleaning up resource....");
		setDisableAll(false);
		stopButton.setDisable(true);
		app.connector.stopEngine();
	}

	@FXML
	public void handleAdd(ActionEvent event) {
		PropertyBounding rowData = (new PropertyBounding());
		propertyTable.getItems().add(rowData);
	}

	@FXML
	public void handleDeletion(ActionEvent event) {
		PropertyBounding selected = propertyTable.getSelectionModel().getSelectedItem();
		propertyTable.getItems().remove(selected);
	}

	public boolean handleSave() {
		try {
			this.app.connector.setKamProperties(propertyFile.getText().trim(), this.propertyTable.getItems());
			this.app.logger.info("### Properties successfully saved:");
			this.app.connector.getKamProperties(propertyFile.getText().trim()).stream()
					.forEach(str -> this.app.logger.info("    " + str));
			return true;
		} catch (Exception e) {
			message(AlertType.ERROR, "Error", "Unable to save the configuration properties: " + e.toString()
					+ ". Please try running it as administrator if possible (shift+right-click on the shortcut).");
			return false;
		}
	}

	@FXML
	public void handleBrowseDataUnit(ActionEvent event) {
		try {

			FileChooser fileChooser = new FileChooser();
			fileChooser.setTitle("Select a file");
			fileChooser.getExtensionFilters().add(new ExtensionFilter("Kam file (*.kam)", "*.kam"));
			File file = fileChooser.showOpenDialog(app.stage);
			if (file == null) {
				app.logger.info("Failed to open the selected file.");
				return;
			}
			URL fxParent = getClass().getResource("forms/CLIPanel.fxml");
			FXMLLoader loader = new FXMLLoader();
			loader.setLocation(fxParent);
			Parent parent = loader.load();
			Tab tab = new Tab();
			tab.textProperty().set("Browsing CLI");
			tabPane.getTabs().add(tab);
			tabPane.getSelectionModel().select(tab);
			tab.setContent(parent);
			CLIPanelController controller = loader.getController();
			controller.browse(this.app, file);
			tab.setOnClosed(evn -> controller.close());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void handleAbout() {
		InputStream url;
		try {
			url = getClass().getClassLoader().getResource("Picture2-32.png").openStream();
			Image image = new Image(url);
			ImageView iv1 = new ImageView(image);
			message(iv1, "About Kam1n0",
					"The software was developed by Steven H. H. Ding and Miles Q. Li under the supervision of Benjamin C. M. Fung at the McGill Data Mining and Security Lab. It is distributed under the Apache License Version 2.0. Please refer to LICENSE.txt for details.\r\n"
							+ "\r\n" + "Copyright 2017 McGill University. All rights reserved.");
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public void message(Alert.AlertType type, String title, String msg) {
		MaterialDesignIcon icon = MaterialDesignIcon.INFORMATION_OUTLINE;
		if (type.equals(AlertType.ERROR))
			icon = MaterialDesignIcon.EXCLAMATION;
		if (type.equals(AlertType.WARNING))
			icon = MaterialDesignIcon.EXCLAMATION;
		MaterialDesignIconView materialDesignIconView = new MaterialDesignIconView(icon);
		materialDesignIconView.setSize("4em");
		message(materialDesignIconView, title, msg);
	}

	public void message(Node icon, String title, String msg) {
		try {

			double centerXPosition = app.stage.getX() + app.stage.getWidth() / 2d;
			double centerYPosition = app.stage.getY() + app.stage.getHeight() / 2d;

			Alert alert = new Alert(Alert.AlertType.INFORMATION);
			alert.setHeaderText(title);
			alert.setContentText(msg);
			DialogPane dialogPane = alert.getDialogPane();
			dialogPane.setGraphic(icon);
			Stage stage = (Stage) dialogPane.getScene().getWindow();
			stage.initStyle(StageStyle.TRANSPARENT);
			dialogPane.getStylesheets().add(getClass().getResource("forms/application.css").toExternalForm());
			dialogPane.getStyleClass().add("myDialog");
			stage.setOnShown(ev -> {
				stage.setX(centerXPosition - stage.getWidth() / 2d);
				stage.setY(centerYPosition - stage.getHeight() / 2d);
				stage.show();
			});
			ColorAdjust adj = new ColorAdjust(0, -0.9, -0.5, 0);
			GaussianBlur blur = new GaussianBlur(15); // 55 is just to show edge effect more clearly.
			adj.setInput(blur);
			Effect original = maskPane.getEffect();
			maskPane.setEffect(adj);
			Rectangle rec = new Rectangle(maskPane.getWidth(), maskPane.getHeight());
			// rec.setX(padding);
			// rec.setY(padding);
			maskPane.setClip(rec);
			stage.showAndWait();
			maskPane.setEffect(original);
			maskPane.setClip(null);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	String normalizePath(String path) {
		return path.replace("\\", "\\\\");
	}

}
