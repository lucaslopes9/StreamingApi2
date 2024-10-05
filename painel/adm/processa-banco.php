<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;


$CadUser = InfoUser(4);
$descricao = empty($_POST['descricao']) ? "" : $_POST['descricao'];
$preco = empty($_POST['preco']) ? "" : trim($_POST['preco']);
$preco = number_format($preco, 2, ',', '');
$referencia = empty($_POST['referencia']) ? "" : $_POST['referencia'];

$SQL = "SELECT banco, tipo, agencia, operacao, conta, favorecido FROM contabancaria WHERE CadUser = :CadUser";
$SQL = $painel_geral->prepare($SQL);
$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
$SQL->execute();

while($Ln = $SQL->fetch()){
	
	
	if($Ln['tipo'] == "C"){
		$tipo = $_TRA['ContaCorrente'];
	}
	else{
		$tipo = $_TRA['ContaPoupanca'];
	}
	
	echo "
						
						<div class=\"form-group\">
							<div class=\"col-md-9\">
							</div>
						</div>
						
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
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Valor']."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							".VerRepDin()." ".$preco."
							</p>
                            </div>
                        </div>


";
}

}else{
	echo Redirecionar('login.php');
}	
?>