<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('EmailadicionarVisualizar', 'EmailadicionarAdicionar', 'EmailadicionarBloquear', 'EmailadicionarEditar', 'EmailadicionarExcluir');
$VerificarAcesso = VerificarAcesso('email_adicionar', $ColunaAcesso);

$EmailadicionarVisualizar = $VerificarAcesso[0];
$EmailadicionarAdicionar = $VerificarAcesso[1];
$EmailadicionarBloquear = $VerificarAcesso[2];
$EmailadicionarEditar = $VerificarAcesso[3];
$EmailadicionarExcluir = $VerificarAcesso[4];

if($EmailadicionarVisualizar == 'S'){
	
$CadUser = InfoUser(2);
$SQL = "SELECT id, exibicao, email, usuario, senha, SMTPSecure, Host, Port, bloqueado FROM email_adicionar WHERE CadUser = :CadUser";
$SQL = $painel_geral->prepare($SQL);
$SQL->bindParam(':CadUser', $CadUser, PDO::PARAM_STR); 
$SQL->execute();
?>

	<!-- START BREADCRUMB -->
                <ul class="breadcrumb">
                	<li><?php echo $_TRA['email']; ?></li>
                    <li class="active"><?php echo $_TRA['Adicionar']; ?></li>
                </ul>
                <!-- END BREADCRUMB -->  
                
                <!-- PAGE TITLE -->
          <div class="page-title">                    
          <h2><span class="fa fa-plus"></span> <?php echo $_TRA['Adicionar']; ?></h2>
          </div>
                <!-- END PAGE TITLE -->   
 
                <!-- PAGE CONTENT WRAPPER -->
                <div class="page-content-wrap">                
                
                    <div class="row">
                        <div class="col-md-12">
                        
                        <div class="panel panel-danger">
                                <div class="panel-heading">
                                <?php
								if($EmailadicionarAdicionar == 'S'){
                                echo "<button onclick=\"AdicionarEmail();\" type=\"button\" class=\"btn btn-info active\">".$_TRA['Adicionar']."</button>";
								}
                                ?>
                                    <ul class="panel-controls">
                                        <li><a href="#" class="panel-fullscreen"><span class="fa fa-expand"></span></a></li>
                                        <li class="dropdown">
                                            <a href="#" class="dropdown-toggle" data-toggle="dropdown" aria-expanded="false"><span class="fa fa-cog"></span></a>                                            
                                            <ul class="dropdown-menu">
                                                <li><a href="#" class="panel-collapse"><span class="fa fa-angle-down"></span> <?php echo $_TRA['esconder']; ?></a></li>
                                                <li><a href="#" class="panel-refresh"><span class="fa fa-refresh"></span> <?php echo $_TRA['atualizar']; ?></a></li>
                                            </ul>                                        
                                        </li>
                                    </ul>
                                </div>
                                <div class="panel-body">
                                                                
                                    <div class="table-responsive">
                               <table id="Tabela" class="table datatable">
                               <thead>
                               		<tr>
                                    	<th width="150"><?php echo $_TRA['Exibicao']; ?></th>
                                        <th><?php echo $_TRA['email']; ?></th>
                                        <th><?php echo $_TRA['Usuario']; ?></th>
                                        <th><?php echo $_TRA['Senha']; ?></th>
                                        <th><?php echo $_TRA['SMTPSecure']; ?></th>
                                        <th><?php echo $_TRA['Servidor']; ?></th>
                                        <th><?php echo $_TRA['Porta']; ?></th>
                                        <th><?php echo $_TRA['opcoes']; ?></th>
                                    </tr>
                                </thead>
                                <tbody>
                                        <?php
										while($Ln = $SQL->fetch()){
										
										if($Ln['bloqueado'] == "S"){
										$status = "&nbsp;&nbsp;<span class=\"pointer label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['Bloqueado']."\">".$_TRA['Bloqueado'][0]."</span>";
										}else{
										$status = "&nbsp;&nbsp;<span class=\"pointer label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['Ativado']."\">".$_TRA['Ativado'][0]."</span>";
										}
										
										echo "
                                        <tr>
											<td>".$Ln['exibicao'].$status."</td>
                                        	<td><span style=\"display: none;\">".$Ln['email']."</span><span class=\"pointer label label-default\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$Ln['email']."\"><i class=\"fa fa-at\"></i></span></td>
                                        	<td><span style=\"display: none;\">".$Ln['usuario']."</span><span class=\"pointer label label-default\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$Ln['usuario']."\"><i class=\"fa fa-users\"></i></span></td>
											<td>".$Ln['senha'][0]."*****</td>
                                        	<td>".$Ln['SMTPSecure']."</td>
                                        	<td>".$Ln['Host']."</td>
											<td>".$Ln['Port']."</td>
                                       	    <td><div class=\"form-group\">";
								
								if($EmailadicionarBloquear == 'S'){
									if($Ln['bloqueado'] == "S"){
									echo "<a onclick=\"DesBloquearEmail('".$Ln['id']."', '".$Ln['email']."');\" class=\"desbloquear label label-success\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['desbloquear']."\"><i class=\"fa fa-unlock-alt\"></i></a>&nbsp;";
									}else{
									echo "<a onclick=\"BloquearEmail('".$Ln['id']."', '".$Ln['email']."');\" class=\"bloquear label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['bloquear']."\"><i class=\"fa fa-lock\"></i></a>&nbsp;";
									}	
								}
								
								if($EmailadicionarEditar == 'S'){
								echo "<a onclick=\"EditarEmail(".$Ln['id'].");\" class=\"editar label label-warning\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['editar']."\"><i class=\"fa fa-pencil\"></i></a>&nbsp;";
								}
								
								if($EmailadicionarExcluir == 'S'){
								echo "<a onclick=\"DeletarEmail('".$Ln['id']."','".$Ln['email']."');\" class=\"label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['excluir']."\"><i class=\"fa fa-trash-o\"></i></a>&nbsp;";
								}
								
									echo "</div>
											
											</td>
                                        </tr>
										";
										}
										?>
                                            </tbody>
                                        </table>
                                    </div>
                                </div>                             
                            </div>



                        </div>
                    </div>                                
                    
                </div>
                <!-- PAGE CONTENT WRAPPER -->      
        
    

		<div id="StatusGeral"></div>        
<!-- START SCRIPTS -->
        <!-- START PLUGINS -->
        <script type="text/javascript" src="js/plugins/jquery/jquery.min.js"></script>
        <script type="text/javascript" src="js/plugins/jquery/jquery-ui.min.js"></script>
        <script type="text/javascript" src="js/plugins/bootstrap/bootstrap.min.js"></script>  
        <!-- END PLUGINS -->

        <!-- START THIS PAGE PLUGINS-->        
        <script type='text/javascript' src='js/plugins/icheck/icheck.min.js'></script>
        <script type="text/javascript" src="js/plugins/mcustomscrollbar/jquery.mCustomScrollbar.min.js"></script>  
        <script type='text/javascript' src='js/plugins/maskedinput/jquery.maskedinput.min.js'></script>  
                <script type="text/javascript" src="js/plugins/datatables/jquery.dataTables.min.js"></script>
        <script type="text/javascript" src="js/DataTables<?php echo Idioma(2); ?>.js"></script>  
        
        <!-- END THIS PAGE PLUGINS-->        

        <!-- START TEMPLATE -->
        <?php include_once("js/settings".Idioma(2).".php"); ?>  
        <script type="text/javascript" src="js/plugins.js"></script>        
        <script type="text/javascript" src="js/actions.js"></script>
        <!-- END TEMPLATE -->
        
        <script type='text/javascript'>  
		<?php
		if($EmailadicionarExcluir == 'S'){
		?>
		function DeletarEmail(id, email){
 		
 				var titulo = '<?php echo $_TRA['excluir']; ?>?';
				var texto = '<?php echo $_TRA['tcqdea']; ?> '+email+'?';
				var tipo = 'danger';
				var url = 'EnviarDeletarEmail';
				var fa = 'fa fa-trash-o';  
			
				$.post('ScriptAlertaJS.php', {id: id, titulo: titulo, texto: texto, tipo: tipo, url: url, fa: fa}, function(resposta) {
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
				});
		}
		<?php
		}
		if($EmailadicionarBloquear == 'S'){
		?>
		function BloquearEmail(id, email){
 		
 				var titulo = '<?php echo $_TRA['bloquear']; ?>?';
				var texto = '<?php echo $_TRA['tcqdba']; ?> '+email+'?';
				var tipo = 'danger';
				var url = 'EnviarBloquearEmail';
				var fa = 'fa fa-lock';  
			
				$.post('ScriptAlertaJS.php', {id: id, titulo: titulo, texto: texto, tipo: tipo, url: url, fa: fa}, function(resposta) {
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
				});
				
		}
		
		function DesBloquearEmail(id, email){
 		
 				var titulo = '<?php echo $_TRA['desbloquear']; ?>?';
				var texto = '<?php echo $_TRA['tcqdda']; ?> '+email+'?';
				var tipo = 'danger';
				var url = 'EnviarDesbloquearEmail';
				var fa = 'fa fa-unlock-alt';  
			
				$.post('ScriptAlertaJS.php', {id: id, titulo: titulo, texto: texto, tipo: tipo, url: url, fa: fa}, function(resposta) {
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
				});
		}
		<?php
		}
		if($EmailadicionarEditar == 'S'){
		?>
		function EditarEmail(id){
 							
				panel_refresh($(".page-container")); 
			
				$.post('ScriptModalEditarEmail.php', {id: id}, function(resposta) {
					
				setTimeout(panel_refresh($(".page-container")),500);
					
					$("#StatusGeral").html('');
					$("#StatusGeral").html(resposta);
				});
		}
		<?php
		}
		if($EmailadicionarAdicionar == 'S'){
		?>
		function AdicionarEmail(){ 
			
				panel_refresh($(".page-container"));
 						
				$.post('ScriptModalAdicionarEmail.php', function(resposta) {
					
				setTimeout(panel_refresh($(".page-container")),500);
					
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
				});
				
		}
		<?php
		}
		?>
		</script>
          

    <!-- END SCRIPTS -->    
<?php
}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}
?>