<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaRev = array('RevVisualizar', 'RevAcesso', 'RevInfo', 'RevMensagem', 'RevBloquear', 'RevDesativar', 'RevEditar', 'RevExcluir', 'RevAdicionar', 'RevLogin');
$VerificarAcesso = VerificarAcesso('rev', $ColunaRev);

$AdminVisualizar = $VerificarAcesso[0];
$AdminAcesso = $VerificarAcesso[1];
$AdminInfo = $VerificarAcesso[2];
$AdminMensagem = $VerificarAcesso[3];
$AdminBloquear = $VerificarAcesso[4];
$AdminDesativar = $VerificarAcesso[5];
$AdminEditar = $VerificarAcesso[6];
$AdminExcluir = $VerificarAcesso[7];
$AdminAdicionar = $VerificarAcesso[8];
$RevLogin = $VerificarAcesso[9];

if($AdminVisualizar == 'S'){
	
$CadUser = (isset($_POST['usuario'])) ? $_POST['usuario'] : '';
$status = (isset($_POST['status'])) ? $_POST['status'] : '';
$PerfilVer = (isset($_POST['perfil'])) ? $_POST['perfil'] : '';

$DataTablesPost = "revendedor-status-processo";
$DataTablesTargets = "{\"targets\": 0,\"orderable\": false}, {\"targets\": 1,\"orderable\": false}, {\"targets\": 9,\"orderable\": false}";
$DataTablesP = "?usuario=".urlencode($CadUser)."&status=".urlencode($status)."&perfil=".urlencode($PerfilVer);
?>

<table id="Tabela" class="table datatable">
                               <thead>
                               		<tr>
                                    	<th width="5"><input type="checkbox" name="TotalAll" id="TotalAll" class="MarcarAll" OnClick="marcardesmarcar();"></th>
                                    	<th><?php echo $_TRA['foto']; ?></th>
                                        <th><?php echo $_TRA['nome']; ?></th>
                                        <th><?php echo $_TRA['user']; ?></th>
                                        <th><?php echo $_TRA['Senha']; ?></th>
                                        <th><?php echo $_TRA['email']; ?></th>
                                        <th><?php echo $_TRA['Perfil']; ?></th>
                                        <th><?php echo $_TRA['DataPremio']; ?></th>
                                        <th><?php echo $_TRA['Login']." ".$_TRA['Ativo']; ?></th>
                                        <th><?php echo $_TRA['cpor']; ?></th>
                                        <?php
										if( ($AdminAcesso == 'S') || ($AdminInfo == 'S') || ($AdminMensagem == 'S') || ($AdminBloquear == 'S') || ($AdminDesativar == 'S') || ($AdminEditar == 'S') || ($AdminExcluir == 'S') ){
                                        echo "<th>".$_TRA['opcoes']."</th>";
										}
										?>
                                    </tr>
                                </thead>
                                <tbody>
                               	<tr style="height: auto;"></tr>
                                </tbody>
                                
            </table>
          
		<!-- START THIS PAGE PLUGINS-->        
        <script type="text/javascript" src="js/plugins/datatables/jquery.dataTables.min.js"></script>
        <?php include_once("js/DataTablesPost".Idioma(2).".php"); ?>
        <!-- END THIS PAGE PLUGINS-->        

<?php
}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}	
?>