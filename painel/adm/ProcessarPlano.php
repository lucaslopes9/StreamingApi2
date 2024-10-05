<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$conexao = empty($_POST['conexao']) ? "" : $_POST['conexao'];
$forma = empty($_POST['forma']) ? "" : $_POST['forma'];
$id = empty($_POST['id']) ? "" : $_POST['id'];
$tipo = empty($_POST['tipo']) ? "N" : $_POST['tipo'];
$CadUser = InfoUser(4);
$AcessoUser = InfoUser(3);

$selecao = $tipo == "S" ? "AND perfil = :perfil" : "AND id = :id";
$tipoplano = $AcessoUser == 2 ? "P" : "N";
$SQL = "SELECT id, nomeplano, tipoperfil, perfil, dias, valor, quantidade FROM planos WHERE CadUser = :CadUser AND tipoplano = :tipoplano ".$selecao."";
$SQL = $painel_geral->prepare($SQL);
$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
$SQL->bindParam(':tipoplano', $tipoplano, PDO::PARAM_STR);
if($tipo == "S") $SQL->bindParam(':perfil', $id, PDO::PARAM_STR);
if($tipo == "N") $SQL->bindParam(':id', $id, PDO::PARAM_STR);
$SQL->execute();
$Ln = $SQL->fetch();

if($Ln['tipoperfil'] == "SAT"){
$ValorCobrado = empty($_SESSION['ValorCobrado']) ? "" : $_SESSION['ValorCobrado'];
}else{
$ValorCobrado = empty($_SESSION['ValorCobradoCab']) ? "" : $_SESSION['ValorCobradoCab'];
}

$dias = $Ln['dias'];
$diasS = $dias > 1 ? $_TRA['dias'] : $_TRA['dia'];

if($tipo == "S"){
	$titulo = $_TRA['paravc']." (30 ". $_TRA['dias'].")";
}
else{
	$titulo = empty($Ln['nomeplano']) ? $_TRA['normal']." (".$dias." ".$diasS.")" : $Ln['nomeplano'];	
}
	
$DiasPre = $tipo == "S" ? "30 ". $_TRA['dias']."" : "".$dias." ".$diasS."";

if($AcessoUser == 2){
	$ValorFinal = $Ln['valor'];
	$PrePago = "S";
}else{
	$ValorFinal = $tipo == "S" ? $ValorCobrado * $conexao : $Ln['valor'] * $conexao;
	$PrePago = "N";
}
$valor = number_format($ValorFinal, 2, ',', '');

$PerfilFinal = $Ln['perfil'];
$perfil = SelecionarPerfil($PerfilFinal);

if($forma == 1){
	$formaExibir = $_TRA['ContaBancaria'];
	$ProcessarPag = "processa-banco.php";
}
elseif($forma == 2){
	$formaExibir = $_TRA['MercadoPago'];
	$ProcessarPag = "processa-mercadopago.php";
}
elseif($forma == 3){
	$formaExibir = $_TRA['PagSeguro'];
	$ProcessarPag = "processa-pagseguro.php";
}
elseif($forma == 4){
	$formaExibir = $_TRA['PayPal'];
	$ProcessarPag = "processa-paypal.php";
}

$quantidade = empty($Ln['quantidade']) ? 0 : $Ln['quantidade'];


echo "<div class=\"modal animated fadeIn\" id=\"ProcessarPlano\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">".$titulo."</h4>
                    </div>
                    <div class=\"modal-body form-horizontal form-group-separated\">     
						<form id=\"validate\" role=\"form\" class=\"StatusBanco AdicionarEmail form-horizontal\" action=\"javascript:MDouglasMS();\">
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Plano']."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							".$titulo."
							</p>
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".ucfirst($_TRA['dias'])."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							".$DiasPre."
							</p>
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Valor']."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							".VerRepDin()." ".$valor."
							</p>
                            </div>
                        </div>";
						
						if( ($AcessoUser == 3) || ($AcessoUser == 4) ){
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['conexao']."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							".$conexao."
							</p>
                            </div>
                        </div>";
						}
						
						if($AcessoUser == 2){
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Quantidade']."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							".$quantidade." ".$_TRA['Login']."
							</p>
                            </div>
                        </div>";
						}
						
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Operadora']."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							".$perfil."
							</p>
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['FormaPag']."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							".$formaExibir."
							</p>
                            </div>
                        </div>
						
						</form>
                    </div>
                    <div class=\"modal-footer\">
						<div id=\"StatusModal\"></div>
						<button type=\"button\" class=\"btn btn-default\" data-dismiss=\"modal\">".$_TRA['Cancelar']."</button>
                        <button type=\"button\" class=\"ConfirmarCompra btn btn-danger\">".$_TRA['Confirmar']."</button>
                    </div>
                </div>
            </div>
        </div>";
		
		$referencia = GerarReferencia();
?>
 
        <script type='text/javascript'> 
       		$("#ProcessarPlano").modal("show");
			
			$(function(){  
				$("button.ConfirmarCompra").click(function() { 
				
					var descricao = '<?php echo $titulo; ?>';
 					var preco = '<?php echo $ValorFinal; ?>';
					var referencia = '<?php echo $referencia; ?>';
					
					pageLoadingFrame("show");
		
					$.post('<?php echo $ProcessarPag; ?>', {descricao: descricao, preco: preco, referencia: referencia}, function(resposta) {
						
						setTimeout(function(){
                        pageLoadingFrame("hide");
						
							<?php
							if($forma == 1){
							?>
							$(".StatusBanco").html(resposta);
							$(".modal-footer").html('');
							<?php
							}
							else{
							?>
							$("#StatusGeral").html(resposta);
							<?php
							}
							?>
               			},1000); 
						
					});
					
				});
			});
		</script>
        
<?php
	if($forma != 1){
	//Adiciona Referência da Compra
	$comprador = InfoUser(2);
	$Dias = $tipo == "S" ? 30 : $dias;

	$SQL = "INSERT INTO comprar (
			CadUser,
            comprador,
            referencia,
			dias,
			valor,
			perfil,
			conexao,
			PrePago,
			Quantidade
            ) VALUES (
            :CadUser,
            :comprador,
            :referencia,
			:dias,
			:valor,
			:perfil,
			:conexao,
			:PrePago,
			:Quantidade
			)";
	$SQL = $painel_geral->prepare($SQL);
	$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_INT);
	$SQL->bindParam(':comprador', $comprador, PDO::PARAM_INT);
	$SQL->bindParam(':referencia', $referencia, PDO::PARAM_STR);
	$SQL->bindParam(':dias', $Dias, PDO::PARAM_STR);
	$SQL->bindParam(':valor', $ValorFinal, PDO::PARAM_STR);
	$SQL->bindParam(':perfil', $PerfilFinal, PDO::PARAM_STR);
	$SQL->bindParam(':conexao', $conexao, PDO::PARAM_STR);
	$SQL->bindParam(':PrePago', $PrePago, PDO::PARAM_STR);
	$SQL->bindParam(':Quantidade', $quantidade, PDO::PARAM_STR);
	$SQL->execute(); 
	}

}else{
	echo Redirecionar('login.php');
}	
?>