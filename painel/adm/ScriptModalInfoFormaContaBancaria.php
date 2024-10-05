<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
global $_TRA;
if(ProtegePag() == true){
	
$ColunaAcesso = array('PagamentoContaBancaria');
$VerificarAcesso = VerificarAcesso('pagamentos', $ColunaAcesso);
$PagamentoContaBancaria = $VerificarAcesso[0];

if($PagamentoContaBancaria == 'S'){
	
$id = (isset($_POST['id'])) ? $_POST['id'] : '';
$CadUser = InfoUser(2);

$SQL = "SELECT id, banco, tipo, agencia, operacao, conta, favorecido FROM contabancaria WHERE CadUser = :CadUser AND id = :id";
$SQL = $painel_geral->prepare($SQL);
$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
$SQL->bindParam(':id', $id, PDO::PARAM_STR);
$SQL->execute();
$Ln = $SQL->fetch();

if($Ln['tipo'] == "C"){
	$tipo = $_TRA['ContaCorrente'];
}
else{
	$tipo = $_TRA['ContaPoupanca'];
}
	
echo "<div class=\"modal animated fadeIn\" id=\"EditarModal\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">".$_TRA['ContaBancaria']."</h4>
                    </div>
                    <div class=\"modal-body form-horizontal form-group-separated\">     
						<form id=\"validate\" role=\"form\" class=\"form-horizontal\" action=\"javascript:MDouglasMS();\">
						
                        <div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Banco']."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							".$Ln['banco']."
							</p>
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Tipo']."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							".$tipo."
							</p>
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Agencia']."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							".$Ln['agencia']."
							</p>
                            </div>
                        </div>";
						
						if($Ln['tipo'] == "P"){
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Operacao']."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							".$Ln['operacao']."
							</p>
                            </div>
                        </div>";
						}
						
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Conta']."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							".$Ln['conta']."
							</p>
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Favorecido']."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							".$Ln['favorecido']."
							</p>
                            </div>
                        </div>
						
						
						</form>
                    </div>
                    <div class=\"modal-footer\">
						<div id=\"StatusModal\"></div>
                        <button type=\"button\" class=\"btn btn-default\" data-dismiss=\"modal\">".$_TRA['fechar']."</button>
                    </div>
                </div>
            </div>
        </div>";
?>



<script>
$("#EditarModal").modal("show");
</script>
   
<?php  
}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}
?>