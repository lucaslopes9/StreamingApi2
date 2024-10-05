<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$Coluna_1 = array('AdminVisualizar');
$VerificarAcesso_1 = VerificarAcesso('admin', $Coluna_1);
$AdminVisualizar = $VerificarAcesso_1[0];

$Coluna_8 = array('RevVisualizar');
$VerificarAcesso_8 = VerificarAcesso('rev', $Coluna_8);
$RevVisualizar = $VerificarAcesso_8[0];
	
$Coluna_9 = array('UserVisualizar');
$VerificarAcesso_9 = VerificarAcesso('user', $Coluna_9);
$UserVisualizar = $VerificarAcesso_9[0];
	
$Coluna_10 = array('TesteVisualizar');
$VerificarAcesso_10 = VerificarAcesso('teste', $Coluna_10);
$TesteVisualizar = $VerificarAcesso_10[0];

if( ($AdminVisualizar == 'S') || ($RevVisualizar == 'S') || ($UserVisualizar == 'S') || ($TesteVisualizar == 'S') ){
	
$CadUser = (isset($_POST['usuario'])) ? $_POST['usuario'] : '';
$status = (isset($_POST['status'])) ? $_POST['status'] : '';
$PerfilVer = (isset($_POST['perfil'])) ? $_POST['perfil'] : '';

$DataTablesPost = "grupos-status-processo";
$DataTablesTargets = "{\"targets\": 0,\"orderable\": false}, {\"targets\": 1,\"orderable\": false}, {\"targets\": 10,\"orderable\": false}";
$DataTablesP = "?usuario=".urlencode($CadUser)."&status=".urlencode($status)."&perfil=".urlencode($PerfilVer);
?>

<table id="Tabela" class="table datatable">
                               <thead>
                               		<tr>
                                    	<th>Grupo</th>
                                    	<th><?php echo $_TRA['foto']; ?></th>
                                        <th><?php echo $_TRA['nome']; ?></th>
                                        <th><?php echo $_TRA['user']; ?></th>
                                        <th><?php echo $_TRA['Senha']; ?></th>
                                        <th><?php echo $_TRA['email']; ?></th>
                                        <th><?php echo $_TRA['Perfil']; ?></th>
                                        <th><?php echo $_TRA['conexao']; ?></th>
                                        <th><?php echo $_TRA['DataPremio']; ?></th>
                                        <th><?php echo $_TRA['cpor']; ?></th>
                                        <th><?php echo $_TRA['opcoes']; ?></th>
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