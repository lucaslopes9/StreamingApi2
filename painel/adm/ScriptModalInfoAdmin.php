<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAdmin = array('AdminInfo');
$VerificarAcesso = VerificarAcesso('admin', $ColunaAdmin);
$AdminInfo = $VerificarAcesso[0];
 
if($AdminInfo == 'S'){
	
$usuario = (isset($_POST['usuario'])) ? $_POST['usuario'] : '';
	
$SQL = "SELECT CadUser, nome, sobrenome, senha, email, celular, foto, perfil, bloqueado, inativo, data_cadastro, data_nascimento FROM admin WHERE usuario = :usuario";
$SQL = $painel_user->prepare($SQL);
$SQL->bindParam(':usuario', $usuario, PDO::PARAM_STR); 
$SQL->execute();
$Ln = $SQL->fetch();

$nome = empty($Ln['nome']) ? "" : $Ln['nome'];
$sobrenome = empty($Ln['sobrenome']) ? "" : $Ln['sobrenome'];
$senha = empty($Ln['senha']) ? "" : $Ln['senha'];
$email = empty($Ln['email']) ? "" : $Ln['email'];
$celular = empty($Ln['celular']) ? "" : $Ln['celular'];
$foto = empty($Ln['foto']) ? "" : $Ln['foto'];
$Foto = Foto($foto);
$ExibirNome = empty($nome) && empty($sobrenome) ? $usuario : $nome."&nbsp;".$sobrenome;
$CadUser = empty($Ln['CadUser']) ? "" : $Ln['CadUser'];
$perfil = empty($Ln['perfil']) ? "" : $Ln['perfil'];
$bloqueado = empty($Ln['bloqueado']) ? "" : $Ln['bloqueado'];
$inativo = empty($Ln['inativo']) ? "" : $Ln['inativo'];
$data_cadastro = empty($Ln['data_cadastro']) || ($Ln['data_cadastro'] == "0000-00-00 00:00:00") ? "" : ConverterData($Ln['data_cadastro'], 1);
$data_nascimento = empty($Ln['data_nascimento']) || ($Ln['data_nascimento'] == "0000-00-00 00:00:00") ? "" : ConverterData($Ln['data_nascimento'], 1);

if($bloqueado == "S"){
$status_bloqueado = "<span class=\"pointer label label-danger label-form\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['sim']."\">".$_TRA['sim']."</span>";
}else{
$status_bloqueado = "<span class=\"pointer label label-success label-form\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['nao']."\">".$_TRA['nao']."</span>";
}

if($inativo == "S"){
$status_inativo = "<span class=\"pointer label label-danger label-form\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['sim']."\">".$_TRA['sim']."</span>";
}else{
$status_inativo = "<span class=\"pointer label label-success label-form\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['nao']."\">".$_TRA['nao']."</span>";
}

echo "<div class=\"modal animated fadeIn\" id=\"EditarModal\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">".$_TRA['informacoes']." (".$usuario.")</h4>
                    </div>
                    <div class=\"modal-body form-horizontal form-group-separated\">     
						<form id=\"validate\" role=\"form\" class=\"form-horizontal\" action=\"javascript:MDouglasMS();\">";
						
						echo "<div class=\"form-group\">
                            <div class=\"col-md-12\">
                        <div class=\"profile\">
                            <div class=\"profile-image\" id=\"profile-image\">
                                <img class=\"pointer\" src=\"".$Foto."\" alt=\"".$ExibirNome."\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$ExibirNome."\" />
                            </div>
							<div class=\"profile-data\">
                                <div class=\"profile-data-name\">".$usuario."</div>
                                <div class=\"profile-data-title\">Cadastrado por ".$CadUser."</div>
                            </div>
                        </div>                                                                        
                            </div>
                        </div>";
						
						if(!empty($nome)){
                        echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['nome']."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							".$nome."
							</p>
                            </div>
                        </div>";
						}
						
						if(!empty($sobrenome)){
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['sobrenome']."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							".$sobrenome."
							</p>
                            </div>
                        </div>";
						}
						
						if(!empty($data_nascimento)){
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['dn']."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							".$data_nascimento."
							</p>
                            </div>
                        </div>";
						}
						
						if(!empty($senha)){
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Senha']."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							".$senha."
							</p>
                            </div>
                        </div>";
						}
						
						if(!empty($email)){
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['email']."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							".$email."
							</p>
                            </div>
                        </div>";
						}
						
						if(!empty($celular)){
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['celular']."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							".$celular."
							</p>
                            </div>
                        </div>";
						}
						
						if(!empty($perfil)){
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Perfil']."</label>
                            <div class=\"col-md-9\">
							".SelecionarPerfil($perfil)."
                            </div>
                        </div>";
						}
						
						if(!empty($bloqueado)){
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Bloqueado']."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							".$status_bloqueado."
							</p>
                            </div>
                        </div>";
						}
						
						if(!empty($inativo)){
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Desativado']."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							".$status_inativo."
							</p>
                            </div>
                        </div>";
						}
						
						if(!empty($data_cadastro)){
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['DataCadastro']."</label>
                            <div class=\"col-md-9\">
							<p class=\"form-control-static\">
							".$data_cadastro."
							</p>
                            </div>
                        </div>";
						}
						
						echo "</form>
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