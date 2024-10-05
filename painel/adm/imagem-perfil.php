<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('ImagemperfilVisualizar', 'ImagemperfilAdicionar', 'ImagemperfilExcluir');
$VerificarAcesso = VerificarAcesso('imagemperfil', $ColunaAcesso);

$ImagemperfilVisualizar = $VerificarAcesso[0];
$ImagemperfilAdicionar = $VerificarAcesso[1];
$ImagemperfilExcluir = $VerificarAcesso[2];

if($ImagemperfilVisualizar == 'S'){

$SQLCSP = "SELECT id, img, nome FROM perfil_icone";
$SQLCSP = $painel_geral->prepare($SQLCSP);
$SQLCSP->execute();
?>

	<link rel="stylesheet" type="text/css" href="css/cropper/cropper.min.css"/>

	<!-- START BREADCRUMB -->
                <ul class="breadcrumb">
                	<li><?php echo $_TRA['CSP']; ?></li>
                    <li class="active"><?php echo $_TRA['ImagemP']; ?></li>
                </ul>
                <!-- END BREADCRUMB -->  
                
                <!-- PAGE TITLE -->
          <div class="page-title">                    
          <h2><span class="fa fa-picture-o"></span> <?php echo $_TRA['ImagemP']; ?></h2>
          </div>
                <!-- END PAGE TITLE -->   
 
                <!-- PAGE CONTENT WRAPPER -->
                <div class="page-content-wrap">                
                
                    <div class="row">
                        <div class="col-md-12">
                        
                        <div class="panel panel-danger">
                                <div class="panel-heading">
                                <?php
								if($ImagemperfilAdicionar == 'S'){
                                echo "<button type=\"button\" class=\"Adicionar btn btn-info active\" data-toggle=\"modal\" data-target=\"#modal_change_photo\">".$_TRA['Adicionar']."</button>";
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
                                    	<th><?php echo $_TRA['nome']; ?></th>
                                        <th><?php echo $_TRA['Imagem']; ?></th>
										<th><?php echo $_TRA['opcoes']; ?></th>
                                    </tr>
                                </thead>
                                <tbody>
                                        <?php
								while($LnCSP = $SQLCSP->fetch()){
								$FotoPerfil = FotoPerfil($LnCSP['img']);
										
										echo "
                                        <tr>
											<td>".ucfirst($LnCSP['nome'])."</td>
											<td><img src=\"".$FotoPerfil."\" height=\"16\" width=\"16\"></td>
                                       	    <td><div class=\"form-group\">";
											
								if($ImagemperfilExcluir == 'S'){								
								echo "<a onclick=\"DeletarPerfil('".$LnCSP['id']."','".$LnCSP['nome']."');\" class=\"label label-danger\" data-toggle=\"tooltip\" data-placement=\"top\" title=\"\" data-original-title=\"".$_TRA['excluir']."\"><i class=\"fa fa-trash-o\"></i></a>&nbsp;";
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
    <?php
	if($ImagemperfilAdicionar == 'S'){
	?>
    <div class="modal animated fadeIn" id="modal_change_photo" tabindex="-1" role="dialog" aria-labelledby="smallModalHead" aria-hidden="true">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <button type="button" class="close" data-dismiss="modal"><span aria-hidden="true">&times;</span><span class="sr-only"><?php echo $_TRA['fechar']; ?></span></button>
                        <h4 class="modal-title" id="smallModalHead"><?php echo $_TRA['af']; ?></h4>
                    </div>                    
                    <form id="cp_crop" method="post" action="javascript:MDouglasMS();">
                    <div class="modal-body">
                        <div class="text-center" id="cp_target"><?php echo $_TRA['fp']; ?></div>
                        <input type="hidden" name="cp_img_path" id="cp_img_path"/>
                        <input type="hidden" name="ic_x" id="ic_x"/>
                        <input type="hidden" name="ic_y" id="ic_y"/>
                        <input type="hidden" name="ic_w" id="ic_w"/>
                        <input type="hidden" name="ic_h" id="ic_h"/>                        
                    </div>                    
                    </form>
                    <form id="cp_upload" method="post" enctype="multipart/form-data" action="upload_perfil.php">
                    <div class="modal-body form-horizontal form-group-separated">
                    
                    	<div class="form-group">
                            <label class="col-md-4 control-label"><?php echo $_TRA['nome']; ?></label>
                            <div class="col-md-6">
                                <input id="NomeImg" name="NomeImg" type="text" class="validate[required] form-control">
                            </div>
                        </div>
                    
                        <div class="form-group">
                            <label class="col-md-4 control-label"><?php echo $_TRA['nf']; ?></label>
                            <div class="col-md-4">
                                <input type="file" class="fileinput btn-info" name="file" id="cp_photo" data-filename-placement="inside" title="<?php echo $_TRA['sf']; ?>"/>
                            </div>                            
                        </div>                              
                    </div>
                    </form>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-success disabled" id="cp_accept"><?php echo $_TRA['aceitar']; ?></button>
                        <button type="button" class="btn btn-default" data-dismiss="modal"><?php echo $_TRA['fechar']; ?></button>
                    </div>
                </div>
            </div>
        </div>
        <?php
		}
		?>

		<div id="StatusGeral"></div>        
	    <!-- START SCRIPTS -->
        <!-- START PLUGINS -->
        <script type="text/javascript" src="js/plugins/jquery/jquery.min.js"></script>
        <script type="text/javascript" src="js/plugins/jquery/jquery-ui.min.js"></script>
        <script type="text/javascript" src="js/plugins/bootstrap/bootstrap.min.js"></script>
        
        <script type="text/javascript" src="js/plugins/jquery/jquery-migrate.min.js"></script>
        <!-- END PLUGINS -->

        <!-- START THIS PAGE PLUGINS-->        
        <script type='text/javascript' src='js/plugins/icheck/icheck.min.js'></script>
        <script type="text/javascript" src="js/plugins/mcustomscrollbar/jquery.mCustomScrollbar.min.js"></script>  
        
        <script type="text/javascript" src="js/plugins/bootstrap/bootstrap-file-input.js"></script>
        <script type="text/javascript" src="js/plugins/form/jquery.form.js"></script>
        
        <script type="text/javascript" src="js/plugins/cropper/cropper.min.js"></script>
		
        <script type='text/javascript' src='js/plugins/validationengine/languages/jquery.validationEngine<?php echo Idioma(2); ?>.js'></script>
        <script type='text/javascript' src='js/plugins/validationengine/jquery.validationEngine.js'></script>     
        
        <script type='text/javascript' src='js/plugins/maskedinput/jquery.maskedinput.min.js'></script>  
        <script type="text/javascript" src="js/plugins/datatables/jquery.dataTables.min.js"></script>
        <script type="text/javascript" src="js/DataTables<?php echo Idioma(2); ?>.js"></script>  
        <!-- END THIS PAGE PLUGINS-->        

        <!-- START TEMPLATE -->
        <?php include_once("js/settings".Idioma(2).".php"); ?>
        <script type="text/javascript" src="js/plugins.js"></script>        
        <script type="text/javascript" src="js/actions.js"></script>
        <?php include_once("js/demo_edit_perfil.php"); ?>
        <!-- END TEMPLATE -->
        
        <script type='text/javascript'>  
		<?php
		if($ImagemperfilExcluir == 'S'){
		?>
		function DeletarPerfil(id, nome){
			 		
 				var titulo = '<?php echo $_TRA['excluir']; ?>?';
				var texto = '<?php echo $_TRA['tcqdea']; ?> '+nome+'?';
				var tipo = 'danger';
				var url = 'EnviarDeletarImagemPerfil';
				var fa = 'fa fa-trash-o';  
							
				$.post('ScriptAlertaJS.php', {id: id, titulo: titulo, texto: texto, tipo: tipo, url: url, fa: fa}, function(resposta) {
					$("#StatusGeral").html('');
					$("#StatusGeral").html(resposta);
				});
		}
		<?php
		}
		?>
		</script> 
<?php
}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}	
?>