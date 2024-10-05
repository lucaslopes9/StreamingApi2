<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaRev = array('UserVisualizar', 'UserInfo', 'UserMensagem', 'UserBloquear', 'UserEditar', 'UserExcluir', 'UserLogin');
$VerificarAcesso = VerificarAcesso('user', $ColunaRev);

$AdminVisualizar = $VerificarAcesso[0];
$AdminInfo = $VerificarAcesso[1];
$AdminMensagem = $VerificarAcesso[2];
$AdminBloquear = $VerificarAcesso[3];
$AdminEditar = $VerificarAcesso[4];
$AdminExcluir = $VerificarAcesso[5];
$UserLogin = $VerificarAcesso[6];

$ColunaRev2 = array('RevVisualizar');
$VerificarAcesso2 = VerificarAcesso('rev', $ColunaRev2);

$AdminVisualizar2 = $VerificarAcesso2[0];

if($AdminVisualizar == 'S'){
	
$CadUser = (isset($_POST['usuario'])) ? $_POST['usuario'] : '';
$status = (isset($_POST['status'])) ? $_POST['status'] : '';
$PerfilVer = (isset($_POST['perfil'])) ? $_POST['perfil'] : '';
$PesquisaEntreData = (isset($_POST['PesquisaEntreData'])) ? $_POST['PesquisaEntreData'] : '';
	
$DataTablesPost = "usuario-status-processo-entre-datas";
$DataTablesTargets = "{\"targets\": 0,\"orderable\": false}, {\"targets\": 1,\"orderable\": false}, {\"targets\": 10,\"orderable\": false}";
$DataTablesP = "?usuario=".urlencode($CadUser)."&status=".urlencode($status)."&perfil=".urlencode($PerfilVer)."&PesquisaEntreData=".urlencode($PesquisaEntreData);
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
                                        <th><?php echo $_TRA['conexao']; ?></th>
                                        <th><?php echo $_TRA['DataPremio']; ?></th>
                                        <th><?php echo $_TRA['cpor']; ?></th>
                                        <?php
										if( ($AdminInfo == 'S') || ($AdminMensagem == 'S') || ($AdminBloquear == 'S') || ($AdminEditar == 'S') || ($AdminExcluir == 'S') || ($AdminVisualizar2 == 'S') ){
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