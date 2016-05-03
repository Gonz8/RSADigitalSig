/**
 * Created by Dominik on 2016-04-26.
 */
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
//import java.security.Signature;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import javafx.application.Application;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.EventHandler;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.chart.NumberAxis;
import javafx.scene.chart.ScatterChart;
import javafx.scene.chart.XYChart;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.scene.paint.CycleMethod;
import javafx.scene.paint.LinearGradient;
import javafx.scene.paint.Stop;
import javafx.scene.shape.Rectangle;
import javafx.scene.text.Font;
import javafx.scene.text.FontWeight;
import javafx.scene.text.Text;
import javafx.stage.Stage;


public class Main extends Application {

    private BorderPane border;
    Stage stage = null;
    TextArea input;
    TextArea output;
    Label pubKeyLbl;
    Label privKeyLbl;
    private int keySize = 1024;
    KeyPair keyPair;
    RSADS sig;



    public static void main(String[] args) {
        launch(args);
    }

    @Override
    public void start(Stage primaryStage) throws Exception {
        primaryStage.setTitle("RSA Digital Signature");
        sig = new RSADS();
        stage = primaryStage;
        border = new BorderPane();
        HBox hbox = addHBox();
        addStackPane(hbox);
        border.setTop(hbox);

        addTextAreaSections();
        addBottomPane();

        Scene scene = new Scene(border, 1000, 350);

        primaryStage.setScene(scene);
        primaryStage.show();
    }

    public HBox addHBox() {
        HBox hbox = new HBox();
        hbox.setPadding(new Insets(15, 12, 15, 12));
        hbox.setSpacing(10);
        hbox.setStyle("-fx-background-color: #336699;");

        Button signBtn = new Button("Sign");
        signBtn.setPrefSize(100, 20);

        signBtn.setOnMouseClicked(new EventHandler<MouseEvent>() {
            @Override
            public void handle(MouseEvent event) {
                signMsg();
            }
        });

        final Button verifyBtn = new Button("Verify");
        verifyBtn.setPrefSize(100, 20);
        verifyBtn.setOnMouseClicked(new EventHandler<MouseEvent>() {
            @Override
            public void handle(MouseEvent event) {
                boolean res = verifyMsg();
                Alert alert = new Alert(Alert.AlertType.INFORMATION);
                alert.setTitle("Signature Verification");
                if (res) {
                    alert.setHeaderText("Valid signature");
                } else {
                    alert.setHeaderText("Invalid signature");
                }
                if (keyPair != null) {
                    alert.showAndWait();
                }
            }
        });

        hbox.getChildren().addAll(signBtn, verifyBtn); //after coma put another objects

        return hbox;
    }


    public void addStackPane(HBox hb) {
        StackPane stack = new StackPane();
        Rectangle helpIcon = new Rectangle(30.0, 25.0);
        helpIcon.setFill(new LinearGradient(0, 0, 0, 1, true, CycleMethod.NO_CYCLE,
                new Stop[]{
                        new Stop(0, Color.web("#4977A3")),
                        new Stop(0.5, Color.web("#B0C6DA")),
                        new Stop(1, Color.web("#9CB6CF")),}));
        helpIcon.setStroke(Color.web("#D0E6FA"));
        helpIcon.setArcHeight(3.5);
        helpIcon.setArcWidth(3.5);

        Text helpText = new Text("?");
        helpText.setFont(Font.font("Verdana", FontWeight.BOLD, 18));
        helpText.setFill(Color.WHITE);
        helpText.setStroke(Color.web("#7080A0"));

        stack.getChildren().addAll(helpIcon, helpText);
        stack.setAlignment(Pos.CENTER_RIGHT);     // Right-justify nodes in stack
        StackPane.setMargin(helpText, new Insets(0, 10, 0, 0)); // Center "?"
        stack.setOnMouseClicked(new EventHandler<MouseEvent>() {
            @Override
            public void handle(MouseEvent event) {
                Alert alert = new Alert(Alert.AlertType.INFORMATION);
                alert.setTitle("Help");
                alert.setHeaderText("Signature generation and verification (RSA algorithm)");
                alert.setContentText("First, press 'Generate keys' button to generate RSA public and private key. Next, you should enter text message into Message section and press 'Sign' button. If Output and Message sections are filled, press 'Verify' button and wait for result of signature verification." );
                alert.showAndWait();
            }
        });
        hb.getChildren().add(stack);            // Add to HBox from Example 1-2
        HBox.setHgrow(stack, Priority.ALWAYS);    // Give stack any extra space
    }

    public void addTextAreaSections () {
        final Label label = new Label("Message");
        label.setFont(new Font("Arial", 20));

        input = new TextArea();
        input.setEditable(true);
        input.setWrapText(false);
        input.setMaxWidth(Double.MAX_VALUE);
        input.setMaxHeight(Double.MAX_VALUE);
        final VBox vbox = new VBox();
        vbox.setSpacing(5);
        vbox.setPadding(new Insets(10, 0, 0, 10));
        vbox.getChildren().addAll(label, input);
        border.setLeft(vbox);

        final Label label2 = new Label("Output");
        label2.setFont(new Font("Arial", 20));

        output = new TextArea();
        output.setEditable(true);
        output.setWrapText(true);
        output.setMinSize(100,100);
        output.setMaxWidth(Double.MAX_VALUE);
        output.setMaxHeight(Double.MAX_VALUE);
        final VBox vbox2 = new VBox();
        vbox2.setSpacing(5);
        vbox2.setPadding(new Insets(10, 10, 10, 10));
        vbox2.getChildren().addAll(label2, output);
        border.setRight(vbox2);
    }

    public void addBottomPane() {
        Button genKeysBtn = new Button("Generate keys");
        genKeysBtn.setPrefSize(100, 20);
        genKeysBtn.setOnMouseClicked(new EventHandler<MouseEvent>() {
            @Override
            public void handle(MouseEvent event) {
                genKeys();
                if(keyPair != null) {
                    String pub = keyPair.getPublic().getEncoded().toString();
                    String priv = keyPair.getPrivate().getEncoded().toString();
                    pubKeyLbl.setText(pub);
                    privKeyLbl.setText(priv);
                }
            }
        });

        final Label labelPub = new Label("Public:");
        labelPub.setFont(new Font("Arial", 14));
        final Label labelPriv = new Label("Private:");
        labelPriv.setFont(new Font("Arial", 14));
        pubKeyLbl = new Label("null");
        pubKeyLbl.setFont(new Font("Arial", 12));
        privKeyLbl = new Label("null");
        privKeyLbl.setFont(new Font("Arial", 12));
        final HBox hb = new HBox();
        hb.setSpacing(5);
        hb.setPadding(new Insets(10, 10, 10, 10));
        hb.getChildren().addAll(genKeysBtn, labelPub, pubKeyLbl, labelPriv, privKeyLbl);
        border.setBottom(hb);
    }


    private void genKeys() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(keySize);
            keyPair = kpg.genKeyPair();
        } catch (NoSuchAlgorithmException nsae) {
            nsae.printStackTrace();
        }
    }

    public void signMsg() {
        if(keyPair != null) {
            try {

                sig.initSign(keyPair.getPrivate());
                sig.update(input.getText().getBytes("UTF8"));
                byte[] signatureBytes = sig.sign();
                output.setText(new BASE64Encoder().encode(signatureBytes));
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setTitle("Error");
            alert.setHeaderText("Keys not generated");
            alert.showAndWait();
        }
    }

    public boolean verifyMsg() {
        boolean result = false;
        if (keyPair != null) {
            try {
                sig.initVerify(keyPair.getPublic());
                sig.update(input.getText().getBytes("UTF8"));

                result = sig.verify(new BASE64Decoder().decodeBuffer(output.getText()));
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setTitle("Error");
            alert.setHeaderText("Keys not generated");
            alert.showAndWait();
        }
        return result;
    }

}